#!/usr/bin/env python3
"""
Threat Intelligence Fetcher (Producer)
Fetches threat indicators from external feeds and publishes to NATS JetStream
"""

import os
import re
import time
import logging
import requests
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
import stix2
import nats
from stix_normalizer import normalize_urlhaus, normalize_threatfox, extract_indicator
from nats.errors import TimeoutError as NATSTimeoutError
from prometheus_client import Counter, Gauge, start_http_server
from flask import Flask, Response
import asyncio

# Configure JSON logging
import logging
import json as json_module

class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""
    def format(self, record):
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': getattr(record, 'module', None),
            'function': getattr(record, 'funcName', None),
            'line': getattr(record, 'lineno', None)
        }
        # Add extra fields if present
        if hasattr(record, 'extra'):
            log_data.update(record.extra)
        return json_module.dumps(log_data)

# Configure logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logger.addHandler(handler)

# Prometheus metrics
threat_feeds_fetched = Counter(
    'threat_feeds_fetched_total',
    'Total number of threat feeds fetched',
    ['source', 'status']
)

threat_indicators_published = Counter(
    'threat_indicators_published_total',
    'Total number of threat indicators published to NATS',
    ['source', 'type']
)

nats_publish_errors = Counter(
    'nats_publish_errors_total',
    'Number of NATS publish errors',
    ['source', 'error_type']
)

feed_last_fetch = Gauge(
    'threat_feed_last_fetch_timestamp',
    'Last successful feed fetch timestamp',
    ['source']
)

# Flask app for metrics
app = Flask(__name__)

@app.route('/metrics')
def metrics():
    """Prometheus metrics endpoint"""
    from prometheus_client import generate_latest
    return Response(generate_latest(), mimetype='text/plain')

@app.route('/health')
def health():
    """Health check endpoint"""
    return {'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()}


class ThreatFeedFetcher:
    """Fetches threat indicators and publishes to NATS JetStream"""

    def __init__(self):
        self.nats_url = os.getenv('NATS_URL', 'nats://nats-client.nats-system:4222')
        self.fetch_interval = int(os.getenv('FETCH_INTERVAL', 300))  # 5 minutes
        self.nc = None
        self.js = None

    async def connect_nats(self):
        """Connect to NATS JetStream with retry logic"""
        max_retries = 5
        retry_delay = 5

        for attempt in range(max_retries):
            try:
                self.nc = await nats.connect(
                    servers=[self.nats_url],
                    name="threat-feed-fetcher",
                    max_reconnect_attempts=60,
                    reconnect_time_wait=2,
                )

                # Enable JetStream context
                self.js = self.nc.jetstream()

                logger.info("Connected to NATS JetStream", extra={
                    'nats_url': self.nats_url
                })
                return True

            except Exception as e:
                logger.warning("NATS connection attempt failed", extra={
                    'attempt': attempt + 1,
                    'max_retries': max_retries,
                    'error': str(e)
                })
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
                else:
                    logger.error("Failed to connect to NATS after all retries")
                    return False
        return False

    def fetch_urlhaus_feed(self) -> List[stix2.Bundle]:
        """
        Fetch malicious URLs from Abuse.ch URLhaus and normalize to STIX 2.1.
        Returns a list of stix2.Bundle objects, one per valid indicator.
        """
        source = 'urlhaus'
        start_time = time.time()

        try:
            feed_url = 'https://urlhaus.abuse.ch/downloads/csv_recent/'
            logger.info("Fetching threat feed", extra={'source': source, 'url': feed_url})

            response = requests.get(feed_url, timeout=30)
            response.raise_for_status()

            bundles = []
            skipped = 0

            for line in response.text.split('\n'):
                if line.startswith('#') or not line.strip():
                    continue
                try:
                    # URLhaus CSV: id, dateadded, url, url_status, threat, tags, urlhaus_link
                    import csv, io
                    row = next(csv.reader(io.StringIO(line)))
                    if len(row) < 7:
                        skipped += 1
                        continue

                    raw = {
                        'id':     row[0].strip(),
                        'url':    row[2].strip(),
                        'threat': row[4].strip(),
                        'tags':   row[5].strip(),
                        'source': source,
                    }

                    bundle = normalize_urlhaus(raw)
                    if bundle:
                        bundles.append(bundle)
                    else:
                        skipped += 1

                except Exception as e:
                    logger.debug(f"Skipping malformed URLhaus line: {e}")
                    skipped += 1
                    continue

            duration_ms = (time.time() - start_time) * 1000
            feed_last_fetch.labels(source=source).set(time.time())
            threat_feeds_fetched.labels(source=source, status='success').inc()

            logger.info("Feed fetch successful", extra={
                'source': source,
                'bundles': len(bundles),
                'skipped': skipped,
                'duration_ms': duration_ms
            })
            return bundles

        except requests.RequestException as e:
            threat_feeds_fetched.labels(source=source, status='failed').inc()
            logger.error("Failed to fetch feed", extra={
                'source': source, 'error_type': 'request_failed'
            }, exc_info=True)
            return []
        except Exception as e:
            threat_feeds_fetched.labels(source=source, status='error').inc()
            logger.error("Unexpected error fetching feed", extra={
                'source': source, 'error_type': 'parse_error'
            }, exc_info=True)
            return []

    def fetch_threatfox_feed(self) -> List[stix2.Bundle]:
        """
        Fetch malicious hosts from Abuse.ch ThreatFox and normalize to STIX 2.1.
        Returns a list of stix2.Bundle objects, one per valid indicator.
        """
        source = 'threatfox'
        start_time = time.time()

        try:
            feed_url = 'https://threatfox.abuse.ch/downloads/hostfile/'
            logger.info("Fetching threat feed", extra={'source': source, 'url': feed_url})

            response = requests.get(feed_url, timeout=30)
            response.raise_for_status()

            bundles = []
            skipped = 0

            for line in response.text.split('\n'):
                if line.startswith('#') or not line.strip():
                    continue
                try:
                    parts = line.split()
                    if len(parts) < 2:
                        skipped += 1
                        continue

                    raw = {
                        'ip':     parts[0],
                        'domain': parts[1],
                        'source': source,
                    }

                    bundle = normalize_threatfox(raw)
                    if bundle:
                        bundles.append(bundle)
                    else:
                        skipped += 1

                except Exception as e:
                    logger.debug(f"Skipping malformed ThreatFox line: {e}")
                    skipped += 1
                    continue

            duration_ms = (time.time() - start_time) * 1000
            feed_last_fetch.labels(source=source).set(time.time())
            threat_feeds_fetched.labels(source=source, status='success').inc()

            logger.info("Feed fetch successful", extra={
                'source': source,
                'bundles': len(bundles),
                'skipped': skipped,
                'duration_ms': duration_ms
            })
            return bundles

        except requests.RequestException as e:
            threat_feeds_fetched.labels(source=source, status='failed').inc()
            logger.error("Failed to fetch feed", extra={
                'source': source, 'error_type': 'request_failed'
            }, exc_info=True)
            return []
        except Exception as e:
            threat_feeds_fetched.labels(source=source, status='error').inc()
            logger.error("Unexpected error fetching feed", extra={
                'source': source, 'error_type': 'parse_error'
            }, exc_info=True)
            return []

    async def publish_bundles(self, bundles: List[stix2.Bundle], source: str):
        """
        Publish STIX 2.1 Bundles to NATS JetStream.

        Subject format: threat.indicators.<source>.<stix_indicator_type>
        Message body:   JSON-serialized STIX Bundle (stix2 library output)
        Dedup key:      indicator STIX ID — deterministic UUID5, same indicator
                        from the same feed always maps to the same NATS-Msg-Id,
                        so JetStream's duplicate window discards re-fetched data.
        """
        if not bundles:
            return

        for bundle in bundles:
            try:
                indicator_obj = extract_indicator(bundle)
                if not indicator_obj:
                    continue

                # Derive a safe subject segment from indicator_types
                # e.g. ["malicious-activity"] → "malicious-activity"
                itype = (indicator_obj.indicator_types or ["unknown"])[0]
                safe_itype = re.sub(r'[^a-zA-Z0-9_-]', '-', itype)

                subject = f"threat.indicators.{source}.{safe_itype}"

                # stix2 library serializes to spec-compliant JSON
                payload = bundle.serialize(pretty=False).encode()

                ack = await self.js.publish(
                    subject,
                    payload,
                    headers={
                        # Deterministic ID → JetStream dedup window works correctly
                        'Nats-Msg-Id': indicator_obj.id,
                        'Source':      source,
                        'Stix-Type':   safe_itype,
                    }
                )

                threat_indicators_published.labels(
                    source=source,
                    type=safe_itype
                ).inc()

                logger.debug("Published STIX bundle to NATS", extra={
                    'source':       source,
                    'indicator_id': indicator_obj.id,
                    'subject':      subject,
                    'stream':       ack.stream,
                    'seq':          ack.seq,
                })

            except NATSTimeoutError:
                nats_publish_errors.labels(source=source, error_type='timeout').inc()
                logger.error("NATS publish timeout", extra={'source': source})
            except Exception as e:
                nats_publish_errors.labels(source=source, error_type='publish_failed').inc()
                logger.error("Failed to publish STIX bundle", extra={
                    'source': source, 'error': str(e)
                })

    async def run(self):
        """Main fetcher loop"""
        logger.info("Starting Threat Intelligence Fetcher (Producer)")

        # Connect to NATS
        if not await self.connect_nats():
            logger.error("Cannot start fetcher without NATS connection")
            return

        logger.info(f"Fetcher will poll feeds every {self.fetch_interval} seconds")

        while True:
            try:
                # Fetch and publish per source so metrics stay source-labelled
                urlhaus_bundles = self.fetch_urlhaus_feed()
                await self.publish_bundles(urlhaus_bundles, source='urlhaus')

                threatfox_bundles = self.fetch_threatfox_feed()
                await self.publish_bundles(threatfox_bundles, source='threatfox')

                total = len(urlhaus_bundles) + len(threatfox_bundles)
                logger.info(f"Published {total} STIX bundles to NATS")

            except Exception as e:
                logger.error(f"Error in fetcher loop: {e}", exc_info=True)

            # Wait before next fetch
            await asyncio.sleep(self.fetch_interval)


def main():
    """Main entry point"""
    import threading

    # Start metrics server in separate thread
    metrics_port = int(os.getenv('METRICS_PORT', 8001))
    logger.info(f"Starting metrics server on port {metrics_port}")

    metrics_thread = threading.Thread(
        target=lambda: app.run(host='0.0.0.0', port=metrics_port),
        daemon=True
    )
    metrics_thread.start()

    # Start fetcher
    fetcher = ThreatFeedFetcher()
    asyncio.run(fetcher.run())


if __name__ == '__main__':
    main()
