#!/usr/bin/env python3
"""
Threat Intelligence Worker
Fetches threat indicators from external feeds and processes them via Redis queue
"""

import os
import time
import logging
import requests
import json
from datetime import datetime
from typing import Dict, List, Any
import redis
from prometheus_client import Counter, Gauge, start_http_server, generate_latest
from flask import Flask, Response

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Prometheus metrics
threat_indicators_processed = Counter(
    'threat_indicators_processed_total',
    'Total number of threat indicators processed',
    ['source', 'type']
)

external_api_errors = Counter(
    'external_api_errors_count',
    'Number of external API errors',
    ['source', 'error_type']
)

feed_last_success = Gauge(
    'threat_feed_last_success_timestamp',
    'Last successful feed fetch timestamp',
    ['source']
)

# Flask app for metrics endpoint
app = Flask(__name__)

@app.route('/metrics')
def metrics():
    """Prometheus metrics endpoint"""
    return Response(generate_latest(), mimetype='text/plain')

@app.route('/health')
def health():
    """Health check endpoint"""
    return {'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()}


class ThreatIntelWorker:
    """Worker for fetching and processing threat intelligence feeds"""

    def __init__(self):
        self.redis_host = os.getenv('REDIS_HOST', 'redis')
        self.redis_port = int(os.getenv('REDIS_PORT', 6379))
        self.redis_client = None
        self.api_key = os.getenv('THREAT_FEED_API_KEY', '')
        self.fetch_interval = int(os.getenv('FETCH_INTERVAL', 300))  # 5 minutes

    def connect_redis(self):
        """Establish Redis connection with retry logic"""
        max_retries = 5
        retry_delay = 5

        for attempt in range(max_retries):
            try:
                self.redis_client = redis.Redis(
                    host=self.redis_host,
                    port=self.redis_port,
                    decode_responses=True,
                    socket_connect_timeout=5
                )
                self.redis_client.ping()
                logger.info(f"Connected to Redis at {self.redis_host}:{self.redis_port}")
                return True
            except redis.ConnectionError as e:
                logger.warning(f"Redis connection attempt {attempt + 1}/{max_retries} failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                else:
                    logger.error("Failed to connect to Redis after all retries")
                    return False
        return False

    def fetch_urlhaus_feed(self) -> List[Dict[str, Any]]:
        """
        Fetch malicious URLs from Abuse.ch URLhaus
        Public feed - no API key required
        """
        source = 'urlhaus'
        try:
            url = 'https://urlhaus.abuse.ch/downloads/csv_recent/'
            logger.info(f"Fetching threat feed from {source}")

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

            feed_last_success.labels(source=source).set(time.time())
            logger.info(f"Fetched {len(indicators)} indicators from {source}")
            return indicators[:100]  # Limit to first 100 for POC

        except requests.RequestException as e:
            logger.error(f"Failed to fetch {source} feed: {e}")
            external_api_errors.labels(source=source, error_type='request_failed').inc()
            return []
        except Exception as e:
            logger.error(f"Unexpected error fetching {source}: {e}")
            external_api_errors.labels(source=source, error_type='parse_error').inc()
            return []

    def fetch_threatfox_feed(self) -> List[Dict[str, Any]]:
        """
        Fetch IOCs from Abuse.ch ThreatFox
        Public feed - no API key required
        """
        source = 'threatfox'
        try:
            url = 'https://threatfox.abuse.ch/downloads/hostfile/'
            logger.info(f"Fetching threat feed from {source}")

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

            feed_last_success.labels(source=source).set(time.time())
            logger.info(f"Fetched {len(indicators)} indicators from {source}")
            return indicators[:100]  # Limit to first 100 for POC

        except requests.RequestException as e:
            logger.error(f"Failed to fetch {source} feed: {e}")
            external_api_errors.labels(source=source, error_type='request_failed').inc()
            return []
        except Exception as e:
            logger.error(f"Unexpected error fetching {source}: {e}")
            external_api_errors.labels(source=source, error_type='parse_error').inc()
            return []

    def process_indicators(self, indicators: List[Dict[str, Any]]):
        """Process and store indicators in Redis"""
        if not indicators:
            return

        for indicator in indicators:
            try:
                # Store in Redis with TTL of 24 hours
                key = f"indicator:{indicator['source']}:{indicator.get('id', hash(str(indicator)))}"
                self.redis_client.setex(
                    key,
                    86400,  # 24 hours TTL
                    json.dumps(indicator)
                )

                # Update metrics
                threat_indicators_processed.labels(
                    source=indicator['source'],
                    type=indicator.get('type', 'unknown')
                ).inc()

            except Exception as e:
                logger.error(f"Failed to process indicator: {e}")

    def run(self):
        """Main worker loop"""
        logger.info("Starting Threat Intelligence Worker")

        # Connect to Redis
        if not self.connect_redis():
            logger.error("Cannot start worker without Redis connection")
            return

        logger.info(f"Worker will fetch feeds every {self.fetch_interval} seconds")

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

                # Process all indicators
                self.process_indicators(all_indicators)

                logger.info(f"Processed {len(all_indicators)} total indicators")

            except Exception as e:
                logger.error(f"Error in worker loop: {e}")

            # Wait before next fetch
            time.sleep(self.fetch_interval)


def main():
    """Main entry point"""
    import threading

    # Start metrics server in separate thread
    metrics_port = int(os.getenv('METRICS_PORT', 8000))
    logger.info(f"Starting metrics server on port {metrics_port}")

    metrics_thread = threading.Thread(
        target=lambda: app.run(host='0.0.0.0', port=metrics_port),
        daemon=True
    )
    metrics_thread.start()

    # Start worker
    worker = ThreatIntelWorker()
    worker.run()


if __name__ == '__main__':
    main()
