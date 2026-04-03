#!/usr/bin/env python3
"""
Threat Intelligence Fetcher (Producer)
Fetches threat indicators from external feeds and publishes to NATS JetStream
"""

import os
import time
import logging
import requests
import json
from datetime import datetime
from typing import Dict, List, Any
import nats
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

    def fetch_urlhaus_feed(self) -> List[Dict[str, Any]]:
        """
        Fetch malicious URLs from Abuse.ch URLhaus
        Public feed - no API key required
        """
        source = 'urlhaus'
        start_time = time.time()

        try:
            url = 'https://urlhaus.abuse.ch/downloads/csv_recent/'
            logger.info("Fetching threat feed", extra={'source': source, 'url': url})

            response = requests.get(url, timeout=30)
            response.raise_for_status()

            # Parse CSV (skip comments)
            indicators = []
            lines = response.text.split('\n')

            for line in lines:
                if line.startswith('#') or not line.strip():
                    continue

                try:
                    parts = line.split(',')
                    if len(parts) >= 7:
                        indicator = {
                            'id': parts[0].strip('"'),
                            'url': parts[2].strip('"'),
                            'threat': parts[4].strip('"'),
                            'tags': parts[5].strip('"'),
                            'source': source,
                            'timestamp': datetime.utcnow().isoformat(),
                            'type': 'malicious_url'
                        }
                        indicators.append(indicator)
                except Exception as e:
                    logger.debug(f"Skipping malformed line: {e}")
                    continue

            duration_ms = (time.time() - start_time) * 1000
            feed_last_fetch.labels(source=source).set(time.time())
            threat_feeds_fetched.labels(source=source, status='success').inc()

            logger.info("Feed fetch successful", extra={
                'source': source,
                'count': len(indicators),
                'duration_ms': duration_ms
            })
            return indicators

        except requests.RequestException as e:
            threat_feeds_fetched.labels(source=source, status='failed').inc()
            logger.error("Failed to fetch feed", extra={
                'source': source,
                'error_type': 'request_failed'
            }, exc_info=True)
            return []
        except Exception as e:
            threat_feeds_fetched.labels(source=source, status='error').inc()
            logger.error("Unexpected error fetching feed", extra={
                'source': source,
                'error_type': 'parse_error'
            }, exc_info=True)
            return []

    def fetch_threatfox_feed(self) -> List[Dict[str, Any]]:
        """
        Fetch IOCs from Abuse.ch ThreatFox
        Public feed - no API key required
        """
        source = 'threatfox'
        start_time = time.time()

        try:
            url = 'https://threatfox.abuse.ch/downloads/hostfile/'
            logger.info("Fetching threat feed", extra={'source': source, 'url': url})

            response = requests.get(url, timeout=30)
            response.raise_for_status()

            indicators = []
            lines = response.text.split('\n')

            for line in lines:
                if line.startswith('#') or not line.strip():
                    continue

                try:
                    parts = line.split()
                    if len(parts) >= 2:
                        indicator = {
                            'ip': parts[0],
                            'domain': parts[1],
                            'source': source,
                            'timestamp': datetime.utcnow().isoformat(),
                            'type': 'malicious_host'
                        }
                        indicators.append(indicator)
                except Exception as e:
                    logger.debug(f"Skipping malformed line: {e}")
                    continue

            duration_ms = (time.time() - start_time) * 1000
            feed_last_fetch.labels(source=source).set(time.time())
            threat_feeds_fetched.labels(source=source, status='success').inc()

            logger.info("Feed fetch successful", extra={
                'source': source,
                'count': len(indicators),
                'duration_ms': duration_ms
            })
            return indicators

        except requests.RequestException as e:
            threat_feeds_fetched.labels(source=source, status='failed').inc()
            logger.error("Failed to fetch feed", extra={
                'source': source,
                'error_type': 'request_failed'
            }, exc_info=True)
            return []
        except Exception as e:
            threat_feeds_fetched.labels(source=source, status='error').inc()
            logger.error("Unexpected error fetching feed", extra={
                'source': source,
                'error_type': 'parse_error'
            }, exc_info=True)
            return []

    async def publish_indicators(self, indicators: List[Dict[str, Any]]):
        """Publish indicators to NATS JetStream"""
        if not indicators:
            return

        for indicator in indicators:
            try:
                # Subject: threat.indicators.<source>.<type>
                subject = f"threat.indicators.{indicator['source']}.{indicator.get('type', 'unknown')}"

                # Publish to JetStream with deduplication
                payload = json.dumps(indicator).encode()

                ack = await self.js.publish(
                    subject,
                    payload,
                    headers={
                        'Nats-Msg-Id': f"{indicator['source']}-{indicator.get('id', hash(str(indicator)))}",
                        'Source': indicator['source'],
                        'Type': indicator.get('type', 'unknown')
                    }
                )

                threat_indicators_published.labels(
                    source=indicator['source'],
                    type=indicator.get('type', 'unknown')
                ).inc()

                logger.debug("Published indicator to NATS", extra={
                    'source': indicator['source'],
                    'subject': subject,
                    'stream': ack.stream,
                    'seq': ack.seq
                })

            except NATSTimeoutError:
                nats_publish_errors.labels(
                    source=indicator.get('source', 'unknown'),
                    error_type='timeout'
                ).inc()
                logger.error("NATS publish timeout", extra={
                    'source': indicator.get('source'),
                })
            except Exception as e:
                nats_publish_errors.labels(
                    source=indicator.get('source', 'unknown'),
                    error_type='publish_failed'
                ).inc()
                logger.error("Failed to publish indicator to NATS", extra={
                    'source': indicator.get('source'),
                    'error': str(e)
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
                # Fetch from multiple sources
                all_indicators = []

                # URLhaus feed
                urlhaus_indicators = self.fetch_urlhaus_feed()
                all_indicators.extend(urlhaus_indicators)

                # ThreatFox feed
                threatfox_indicators = self.fetch_threatfox_feed()
                all_indicators.extend(threatfox_indicators)

                # Publish to NATS JetStream
                await self.publish_indicators(all_indicators)

                logger.info(f"Published {len(all_indicators)} total indicators to NATS")

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
