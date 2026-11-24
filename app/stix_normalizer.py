#!/usr/bin/env python3
"""
STIX 2.1 Normalizer

Converts raw threat feed data into STIX 2.1 Bundles.
Each public function takes a raw dict from a feed parser and returns
a stix2.Bundle (or None if the input is invalid/unparseable).

STIX objects produced per feed:
  URLhaus  → URL (SCO) + Indicator (SDO)
  ThreatFox → IPv4Address and/or DomainName (SCO) + Indicator (SDO)

IDs are deterministic (UUID5) so the same indicator from the same
source always produces the same STIX ID — enabling deduplication
at the Redis storage layer without a separate lookup.
"""

import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import stix2

# How long an indicator is considered valid after ingestion.
# For a 24-hour TTL store, 30 days gives downstream consumers
# enough context even if they query near expiry.
_VALID_FOR_DAYS = 30

# UUID5 namespace: fixed, private to this application.
# Using NAMESPACE_DNS is conventional; the actual namespace UUID
# just needs to be stable and unique to your org.
_NS = uuid.UUID("12345678-1234-5678-1234-567812345678")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def normalize_urlhaus(raw: Dict[str, Any]) -> Optional[stix2.Bundle]:
    """
    Convert a URLhaus CSV row dict into a STIX 2.1 Bundle.

    Expected raw fields:
        id       – URLhaus numeric ID
        url      – the malicious URL string
        threat   – URLhaus threat classification
        tags     – comma-separated tag string
        source   – always 'urlhaus'

    Returns None when the URL value is missing or obviously invalid.
    """
    url_value = raw.get("url", "").strip()
    if not url_value or not url_value.startswith(("http://", "https://")):
        return None

    now = datetime.now(timezone.utc)
    valid_until = now + timedelta(days=_VALID_FOR_DAYS)

    url_obj = stix2.URL(
        id=f"url--{_uuid5('urlhaus:url', url_value)}",
        value=url_value,
    )

    threat = raw.get("threat", "").lower()

    indicator = stix2.Indicator(
        id=f"indicator--{_uuid5('urlhaus:indicator', url_value)}",
        spec_version="2.1",
        name=f"Malicious URL: {url_value[:80]}",
        description=(
            f"Malicious URL identified by URLhaus. "
            f"Threat classification: {threat or 'unclassified'}."
        ),
        # STIX pattern — the core machine-readable part of STIX 2.1
        pattern=f"[url:value = '{_stix_escape(url_value)}']",
        pattern_type="stix",
        valid_from=now,
        valid_until=valid_until,
        indicator_types=_urlhaus_indicator_types(threat),
        labels=_split_tags(raw.get("tags", "")),
        external_references=[
            stix2.ExternalReference(
                source_name="URLhaus",
                url=f"https://urlhaus.abuse.ch/url/{raw.get('id', '')}/"
            )
        ],
        # TLP:WHITE — public feed, no distribution restriction
        object_marking_refs=[stix2.TLP_WHITE],
        # Custom properties (x_ prefix is required by STIX spec for extensions)
        custom_properties={
            "x_feed_source": "urlhaus",
            "x_original_id": str(raw.get("id", "")),
            "x_ingested_at": now.isoformat(),
        },
    )

    return stix2.Bundle(
        id=f"bundle--{uuid.uuid4()}",
        objects=[url_obj, indicator],
        allow_custom=True,
    )


def normalize_threatfox(raw: Dict[str, Any]) -> Optional[stix2.Bundle]:
    """
    Convert a ThreatFox hostfile row dict into a STIX 2.1 Bundle.

    Expected raw fields:
        ip     – IPv4 address string (may be empty)
        domain – hostname string (may be empty)
        source – always 'threatfox'

    Produces one SCO per valid field (IPv4Address, DomainName) plus
    a single Indicator whose pattern ORs all observables together.

    Returns None when neither ip nor domain yields a valid observable.
    """
    ip_raw = raw.get("ip", "").strip()
    domain_raw = raw.get("domain", "").strip()

    now = datetime.now(timezone.utc)
    valid_until = now + timedelta(days=_VALID_FOR_DAYS)

    scos: List[stix2.v21._STIXBase] = []
    pattern_clauses: List[str] = []

    if ip_raw and _valid_ipv4(ip_raw):
        scos.append(
            stix2.IPv4Address(
                id=f"ipv4-addr--{_uuid5('threatfox:ip', ip_raw)}",
                value=ip_raw,
            )
        )
        pattern_clauses.append(f"ipv4-addr:value = '{ip_raw}'")

    if domain_raw and _valid_domain(domain_raw):
        scos.append(
            stix2.DomainName(
                id=f"domain-name--{_uuid5('threatfox:domain', domain_raw)}",
                value=domain_raw,
            )
        )
        pattern_clauses.append(f"domain-name:value = '{_stix_escape(domain_raw)}'")

    if not pattern_clauses:
        return None

    # When both IP and domain are present, the indicator fires on either
    pattern = "[" + " OR ".join(pattern_clauses) + "]"

    # Deterministic indicator ID keyed on the primary observable
    dedup_value = ip_raw or domain_raw
    indicator = stix2.Indicator(
        id=f"indicator--{_uuid5('threatfox:indicator', dedup_value)}",
        spec_version="2.1",
        name=f"Malicious Host: {domain_raw or ip_raw}",
        description="Malicious host identified by ThreatFox.",
        pattern=pattern,
        pattern_type="stix",
        valid_from=now,
        valid_until=valid_until,
        indicator_types=["malicious-activity"],
        external_references=[
            stix2.ExternalReference(source_name="ThreatFox")
        ],
        object_marking_refs=[stix2.TLP_WHITE],
        custom_properties={
            "x_feed_source": "threatfox",
            "x_ingested_at": now.isoformat(),
        },
    )

    return stix2.Bundle(
        id=f"bundle--{uuid.uuid4()}",
        objects=[*scos, indicator],
        allow_custom=True,
    )


def extract_indicator(bundle: stix2.Bundle) -> Optional[stix2.Indicator]:
    """
    Pull the first Indicator SDO out of a Bundle.
    Used by the processor to get the canonical ID for Redis keying.
    """
    for obj in bundle.objects:
        if obj.type == "indicator":
            return obj
    return None


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _uuid5(namespace_suffix: str, value: str) -> str:
    """
    Generate a deterministic UUID5 from a namespaced key + value.
    Same inputs always produce the same UUID across processes and restarts.
    Unlike Python's hash(), UUID5 is stable and cryptographically defined.
    """
    key = f"{namespace_suffix}:{value}"
    return str(uuid.uuid5(_NS, key))


def _stix_escape(value: str) -> str:
    """
    Escape a string value for safe embedding inside a STIX pattern.
    STIX patterns use single quotes; backslash is the escape character.
    """
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _urlhaus_indicator_types(threat: str) -> List[str]:
    _map = {
        "malware_download": ["malicious-activity"],
        "botnet_cc":        ["malicious-activity", "compromised"],
        "phishing":         ["phishing"],
        "exploit":          ["malicious-activity", "exploit-target"],
    }
    return _map.get(threat, ["malicious-activity"])


def _split_tags(tags_str: str) -> List[str]:
    if not tags_str:
        return []
    return [t.strip().lower() for t in tags_str.split(",") if t.strip()][:10]


def _valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _valid_domain(value: str) -> bool:
    return bool(
        re.match(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$",
            value,
        )
    )
