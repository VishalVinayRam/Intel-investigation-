#!/usr/bin/env python3
"""
Load Test Script — Intel Ingestion Pipeline
Publishes a high volume of synthetic threat indicators to NATS JetStream
and reports throughput, latency, and error statistics.

Usage:
    python scripts/load-test.py --messages 10000 --concurrency 20
    python scripts/load-test.py --messages 50000 --concurrency 50 --nats-url nats://localhost:4222

Requirements:
    pip install nats-py
"""

import asyncio
import argparse
import json
import random
import string
import time
import sys
from datetime import datetime
from dataclasses import dataclass, field
from typing import List

try:
    import nats
    from nats.errors import TimeoutError as NATSTimeoutError
except ImportError:
    print("ERROR: nats-py not installed. Run: pip install nats-py")
    sys.exit(1)


# ─── Synthetic Data Generators ────────────────────────────────────────────────

TLD_LIST = [".com", ".net", ".org", ".ru", ".cn", ".io", ".xyz", ".top"]
THREAT_TAGS = ["malware", "botnet", "phishing", "ransomware", "exploit", "c2", "trojan"]
THREAT_TYPES = ["malware_download", "phishing", "exploit_kit", "botnet_cc"]


def random_ip() -> str:
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def random_domain() -> str:
    length = random.randint(5, 14)
    name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    return name + random.choice(TLD_LIST)


def random_url() -> str:
    domain = random_domain()
    path_len = random.randint(4, 12)
    path = ''.join(random.choices(string.ascii_lowercase + string.digits, k=path_len))
    return f"http://{domain}/{path}"


def random_id() -> str:
    return ''.join(random.choices(string.digits, k=7))


def make_malicious_url_indicator() -> dict:
    return {
        "id": random_id(),
        "url": random_url(),
        "threat": random.choice(THREAT_TYPES),
        "tags": random.choice(THREAT_TAGS),
        "source": "urlhaus",
        "timestamp": datetime.utcnow().isoformat(),
        "type": "malicious_url"
    }


def make_malicious_host_indicator() -> dict:
    return {
        "ip": random_ip(),
        "domain": random_domain(),
        "source": "threatfox",
        "timestamp": datetime.utcnow().isoformat(),
        "type": "malicious_host"
    }


def make_indicator() -> dict:
    """Randomly pick an indicator type."""
    if random.random() < 0.6:
        return make_malicious_url_indicator()
    return make_malicious_host_indicator()


# ─── Stats Tracker ────────────────────────────────────────────────────────────

@dataclass
class Stats:
    total: int = 0
    sent: int = 0
    failed: int = 0
    latencies: List[float] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)

    def record_success(self, latency_ms: float):
        self.sent += 1
        self.latencies.append(latency_ms)

    def record_failure(self):
        self.failed += 1

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time

    @property
    def rate(self) -> float:
        if self.elapsed == 0:
            return 0
        return self.sent / self.elapsed

    def percentile(self, p: float) -> float:
        if not self.latencies:
            return 0
        sorted_lat = sorted(self.latencies)
        idx = int(len(sorted_lat) * p / 100)
        return sorted_lat[min(idx, len(sorted_lat) - 1)]

    def print_progress(self):
        done = self.sent + self.failed
        pct = (done / self.total * 100) if self.total else 0
        bar_len = 30
        filled = int(bar_len * pct / 100)
        bar = '█' * filled + '░' * (bar_len - filled)
        sys.stdout.write(
            f"\r  [{bar}] {pct:5.1f}%  "
            f"{done:>{len(str(self.total))}}/{self.total}  "
            f"{self.rate:6.0f} msg/s  "
            f"errors: {self.failed}"
        )
        sys.stdout.flush()

    def print_summary(self):
        print(f"\n\n{'═' * 60}")
        print(f"  LOAD TEST RESULTS")
        print(f"{'═' * 60}")
        print(f"  Total messages attempted : {self.total}")
        print(f"  Successfully published   : {self.sent}")
        print(f"  Failed                   : {self.failed}")
        print(f"  Elapsed time             : {self.elapsed:.2f}s")
        print(f"  Throughput               : {self.rate:.1f} msg/s")
        print(f"{'─' * 60}")
        if self.latencies:
            print(f"  Publish latency (ms)")
            print(f"    Min  : {min(self.latencies):.2f} ms")
            print(f"    p50  : {self.percentile(50):.2f} ms")
            print(f"    p95  : {self.percentile(95):.2f} ms")
            print(f"    p99  : {self.percentile(99):.2f} ms")
            print(f"    Max  : {max(self.latencies):.2f} ms")
        print(f"{'═' * 60}\n")


# ─── Publisher ────────────────────────────────────────────────────────────────

async def publish_batch(js, indicators: list, stats: Stats, semaphore: asyncio.Semaphore):
    """Publish a batch of indicators, respecting concurrency limit."""
    tasks = []
    for indicator in indicators:
        tasks.append(publish_one(js, indicator, stats, semaphore))
    await asyncio.gather(*tasks)


async def publish_one(js, indicator: dict, stats: Stats, semaphore: asyncio.Semaphore):
    """Publish a single indicator to NATS JetStream."""
    async with semaphore:
        subject = f"threat.indicators.{indicator['source']}.{indicator.get('type', 'unknown')}"
        payload = json.dumps(indicator).encode()
        msg_id = f"{indicator['source']}-{indicator.get('id', hash(str(indicator)))}-{random.randint(0,999999)}"

        t0 = time.perf_counter()
        try:
            await js.publish(
                subject,
                payload,
                headers={"Nats-Msg-Id": msg_id}
            )
            latency_ms = (time.perf_counter() - t0) * 1000
            stats.record_success(latency_ms)
        except NATSTimeoutError:
            stats.record_failure()
        except Exception:
            stats.record_failure()


# ─── Main ─────────────────────────────────────────────────────────────────────

async def run(args):
    print(f"\n{'═' * 60}")
    print(f"  Intel Pipeline Load Test")
    print(f"{'═' * 60}")
    print(f"  NATS URL     : {args.nats_url}")
    print(f"  Messages     : {args.messages}")
    print(f"  Concurrency  : {args.concurrency}")
    print(f"  Batch size   : {args.batch_size}")
    print(f"{'═' * 60}\n")

    # Connect to NATS
    print("  Connecting to NATS...", end=" ")
    try:
        nc = await nats.connect(
            servers=[args.nats_url],
            name="load-tester",
            connect_timeout=5,
            max_reconnect_attempts=3,
        )
        js = nc.jetstream()
        print("connected.")
    except Exception as e:
        print(f"FAILED\n  Error: {e}")
        print(f"\n  Make sure NATS is reachable at {args.nats_url}")
        print(f"  For local minikube: kubectl port-forward svc/nats-client 4222:4222 -n nats-system\n")
        return

    stats = Stats(total=args.messages)
    semaphore = asyncio.Semaphore(args.concurrency)

    print(f"  Publishing {args.messages} indicators...\n")

    # Generate and publish in batches
    remaining = args.messages
    while remaining > 0:
        batch_count = min(args.batch_size, remaining)
        batch = [make_indicator() for _ in range(batch_count)]
        await publish_batch(js, batch, stats, semaphore)
        remaining -= batch_count
        stats.print_progress()

    stats.print_progress()
    await nc.close()
    stats.print_summary()

    # Guidance on what to watch
    print("  What to watch in Grafana:")
    print("  ┌─────────────────────────────────────────────────────┐")
    print("  │  Panel                     │  Expected behaviour    │")
    print("  ├─────────────────────────────────────────────────────┤")
    print("  │  NATS Queue Backlog        │  Spikes then drains    │")
    print("  │  Throughput (consumed/min) │  Rises sharply         │")
    print("  │  Processor Replica Count   │  HPA scales up         │")
    print("  │  Processing Duration p99   │  Watch for slowdown    │")
    print("  │  Redis Storage ops/min     │  Mirrors processed/min │")
    print("  │  Traces (Tempo panel)      │  New spans appear      │")
    print("  └─────────────────────────────────────────────────────┘")
    print(f"\n  Open Grafana → Intel Pipeline dashboard to observe.\n")


def main():
    parser = argparse.ArgumentParser(
        description="Load test the Intel Ingestion Pipeline via NATS JetStream"
    )
    parser.add_argument(
        "--messages", type=int, default=5000,
        help="Total number of indicators to publish (default: 5000)"
    )
    parser.add_argument(
        "--concurrency", type=int, default=20,
        help="Max concurrent in-flight publishes (default: 20)"
    )
    parser.add_argument(
        "--batch-size", type=int, default=200,
        help="How many indicators to generate per iteration (default: 200)"
    )
    parser.add_argument(
        "--nats-url", type=str, default="nats://localhost:4222",
        help="NATS server URL (default: nats://localhost:4222)"
    )
    args = parser.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
