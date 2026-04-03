#!/usr/bin/env python3
"""
Threat Intelligence Processor (Consumer)
Consumes threat indicators from NATS JetStream and processes them
"""

import os
import time
import logging
import json
import redis
from datetime import datetime
from typing import Dict, Any
import nats
from nats.errors import TimeoutError as NATSTimeoutError
from nats.js.errors import NotFoundError
from prometheus_client import Counter, Histogram, Gauge, start_http_server
from flask import Flask, Response
import asyncio

# Configure JSON logging
import logging
import json

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
        return json.dumps(log_data)

# Configure logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logger.addHandler(handler)

# OpenTelemetry imports
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.instrumentation.redis import RedisInstrumentor

# Prometheus metrics
indicators_consumed = Counter(
    'threat_indicators_consumed_total',
    'Total number of threat indicators consumed from NATS',
    ['source', 'type']
)

indicators_processed = Counter(
    'threat_indicators_processed_total',
    'Total number of threat indicators processed successfully',
    ['source', 'type']
)

indicators_failed = Counter(
    'threat_indicators_failed_total',
    'Total number of failed indicator processing attempts',
    ['source', 'error_type']
)

processing_duration = Histogram(
    'indicator_processing_duration_seconds',
    'Time spent processing indicators',
    ['source', 'type']
)

nats_message_errors = Counter(
    'nats_message_errors_total',
    'Number of NATS message processing errors',
    ['error_type']
)

redis_storage_operations = Counter(
    'redis_storage_operations_total',
    'Redis storage operations',
    ['operation', 'status']
)

queue_backlog = Gauge(
    'nats_queue_backlog',
    'Number of pending messages in NATS queue'
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


def setup_tracing():
    """Configure OpenTelemetry tracing for Tempo"""
    tempo_endpoint = os.getenv('TEMPO_ENDPOINT', 'tempo.monitoring.svc.cluster.local:4317')

    provider = TracerProvider(
        resource=Resource.create({
            "service.name": "intel-processor",
            "service.version": "1.0.0",
            "environment": os.getenv('ENVIRONMENT', 'poc')
        })
    )

    otlp_exporter = OTLPSpanExporter(
        endpoint=tempo_endpoint,
        insecure=True
    )

    provider.add_span_processor(BatchSpanProcessor(otlp_exporter))
    trace.set_tracer_provider(provider)

    # Instrument Redis
    RedisInstrumentor().instrument()

    logger.info("OpenTelemetry tracing configured", extra={
        'tempo_endpoint': tempo_endpoint
    })

# Initialize tracer
tracer = trace.get_tracer(__name__)


class ThreatIndicatorProcessor:
    """Processes threat indicators from NATS JetStream"""

    def __init__(self):
        self.nats_url = os.getenv('NATS_URL', 'nats://nats-client.nats-system:4222')
        self.redis_host = os.getenv('REDIS_HOST', 'redis')
        self.redis_port = int(os.getenv('REDIS_PORT', 6379))
        self.batch_size = int(os.getenv('BATCH_SIZE', 10))
        self.nc = None
        self.js = None
        self.redis_client = None
        self.consumer_name = os.getenv('CONSUMER_NAME', 'processor-group')
        self.stream_name = 'THREAT_INDICATORS'

    async def connect_nats(self):
        """Connect to NATS JetStream with retry logic"""
        max_retries = 5
        retry_delay = 5

        for attempt in range(max_retries):
            try:
                self.nc = await nats.connect(
                    servers=[self.nats_url],
                    name="threat-processor",
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

    def connect_redis(self):
        """Connect to Redis with rotation support and retry logic"""
        max_retries = 5
        retry_delay = 5

        # Initial password load from volume mount (for rotation)
        password_path = os.getenv('REDIS_PASSWORD_FILE', '/etc/secrets/REDIS_PASSWORD')
        self.redis_password = os.getenv('REDIS_PASSWORD', '')

        for attempt in range(max_retries):
            try:
                # Reload password from file in case it was rotated during retry loop
                if os.path.exists(password_path):
                    with open(password_path, 'r') as f:
                        self.redis_password = f.read().strip()

                self.redis_client = redis.Redis(
                    host=self.redis_host,
                    port=self.redis_port,
                    password=self.redis_password if self.redis_password else None,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5
                )

                # Test connection
                self.redis_client.ping()
                logger.info("Connected to Redis", extra={
                    'redis_host': self.redis_host,
                    'redis_port': self.redis_port,
                    'is_authenticated': bool(self.redis_password)
                })
                return True

            except redis.RedisError as e:
                logger.warning("Redis connection attempt failed", extra={
                    'attempt': attempt + 1,
                    'max_retries': max_retries,
                    'error': str(e)
                })
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                else:
                    logger.error("Failed to connect to Redis after all retries")
                    return False
        return False

    def process_indicator(self, indicator: Dict[str, Any]) -> bool:
        """
        Process a single threat indicator
        Returns True if successfully processed, False otherwise
        """
        source = indicator.get('source', 'unknown')
        indicator_type = indicator.get('type', 'unknown')

        with tracer.start_as_current_span("process_indicator") as span:
            span.set_attribute("indicator.source", source)
            span.set_attribute("indicator.type", indicator_type)

            start_time = time.time()

            try:
                # Extract key fields based on type
                if indicator_type == 'malicious_url':
                    key = f"threat:url:{indicator.get('url', 'unknown')}"
                    value = json.dumps({
                        'id': indicator.get('id'),
                        'url': indicator.get('url'),
                        'threat': indicator.get('threat'),
                        'tags': indicator.get('tags'),
                        'source': source,
                        'timestamp': indicator.get('timestamp'),
                        'type': indicator_type
                    })

                elif indicator_type == 'malicious_host':
                    key = f"threat:host:{indicator.get('domain', 'unknown')}"
                    value = json.dumps({
                        'ip': indicator.get('ip'),
                        'domain': indicator.get('domain'),
                        'source': source,
                        'timestamp': indicator.get('timestamp'),
                        'type': indicator_type
                    })

                else:
                    # Generic indicator
                    key = f"threat:generic:{source}:{indicator.get('id', hash(str(indicator)))}"
                    value = json.dumps(indicator)

                # Store in Redis with 24h TTL
                with tracer.start_as_current_span("redis_store"):
                    self.redis_client.setex(
                        key,
                        86400,  # 24 hours
                        value
                    )

                redis_storage_operations.labels(operation='set', status='success').inc()

                # Update metrics
                duration = time.time() - start_time
                processing_duration.labels(source=source, type=indicator_type).observe(duration)
                indicators_processed.labels(source=source, type=indicator_type).inc()

                span.set_attribute("processing.duration_ms", duration * 1000)
                span.set_attribute("redis.key", key)

                logger.debug("Indicator processed successfully", extra={
                    'source': source,
                    'type': indicator_type,
                    'duration_ms': duration * 1000
                })

                return True

            except redis.RedisError as e:
                redis_storage_operations.labels(operation='set', status='failed').inc()
                indicators_failed.labels(source=source, error_type='redis_error').inc()
                logger.error("Redis storage error", extra={
                    'source': source,
                    'type': indicator_type,
                    'error': str(e)
                })
                span.record_exception(e)
                return False

            except Exception as e:
                indicators_failed.labels(source=source, error_type='processing_error').inc()
                logger.error("Indicator processing error", extra={
                    'source': source,
                    'type': indicator_type,
                    'error': str(e)
                })
                span.record_exception(e)
                return False

    async def consume_messages(self):
        """Consume messages from NATS JetStream pull consumer"""
        logger.info("Starting message consumption", extra={
            'stream': self.stream_name,
            'consumer': self.consumer_name,
            'batch_size': self.batch_size
        })

        try:
            # Subscribe to the consumer
            subscription = await self.js.pull_subscribe(
                subject="threat.indicators.>",
                durable=self.consumer_name,
                stream=self.stream_name
            )

            iteration = 0
            while True:
                iteration += 1
                # Periodically check for key rotation (every 10 batches)
                if iteration % 10 == 0:
                    await self.check_key_rotation()

                try:
                    # Fetch batch of messages
                    with tracer.start_as_current_span("fetch_batch") as span:
                        messages = await subscription.fetch(
                            batch=self.batch_size,
                            timeout=5
                        )

                        span.set_attribute("batch.size", len(messages))

                        logger.debug(f"Fetched {len(messages)} messages from queue")

                        # Process each message
                        for msg in messages:
                            with tracer.start_as_current_span("process_message") as msg_span:
                                try:
                                    # Parse indicator
                                    indicator = json.loads(msg.data.decode())

                                    source = indicator.get('source', 'unknown')
                                    indicator_type = indicator.get('type', 'unknown')

                                    msg_span.set_attribute("message.subject", msg.subject)
                                    msg_span.set_attribute("indicator.source", source)
                                    msg_span.set_attribute("indicator.type", indicator_type)

                                    indicators_consumed.labels(source=source, type=indicator_type).inc()

                                    # Process the indicator
                                    success = self.process_indicator(indicator)

                                    if success:
                                        # Acknowledge successful processing
                                        await msg.ack()
                                        logger.debug("Message acknowledged", extra={
                                            'subject': msg.subject,
                                            'source': source
                                        })
                                    else:
                                        # Negative acknowledgment - will be redelivered
                                        await msg.nak()
                                        logger.warning("Message processing failed, will retry", extra={
                                            'subject': msg.subject,
                                            'source': source
                                        })

                                except json.JSONDecodeError as e:
                                    nats_message_errors.labels(error_type='json_decode').inc()
                                    logger.error("Failed to decode message", extra={
                                        'error': str(e)
                                    })
                                    # Terminate the message - malformed, no point retrying
                                    await msg.term()

                                except Exception as e:
                                    nats_message_errors.labels(error_type='processing_error').inc()
                                    logger.error("Message processing error", extra={
                                        'error': str(e)
                                    })
                                    # Negative ack for retry
                                    await msg.nak()

                except NATSTimeoutError:
                    # No messages available, continue polling
                    logger.debug("No messages in queue, waiting...")
                    await asyncio.sleep(1)

                except NotFoundError:
                    logger.error("Consumer not found, may need to recreate")
                    await asyncio.sleep(10)

                except Exception as e:
                    logger.error("Error fetching messages", extra={
                        'error': str(e)
                    })
                    await asyncio.sleep(5)

        except Exception as e:
            logger.error("Fatal error in consumer loop", exc_info=True)
            raise

    async def check_key_rotation(self):
        """Check for rotated keys in mounted secrets."""
        password_path = os.getenv('REDIS_PASSWORD_FILE', '/etc/secrets/REDIS_PASSWORD')
        if os.path.exists(password_path):
            try:
                with open(password_path, 'r') as f:
                    new_password = f.read().strip()
                if new_password != self.redis_password:
                    logger.info("Key rotation detected! Reconnecting to Redis...")
                    self.redis_password = new_password
                    self.connect_redis()
            except Exception as e:
                logger.error("Error during key rotation check", extra={"error": str(e)})

    async def get_stream_info(self):
        """Get stream information for monitoring"""
        try:
            stream_info = await self.js.stream_info(self.stream_name)

            # Update backlog metric
            pending = stream_info.state.messages
            queue_backlog.set(pending)

            logger.info("Stream status", extra={
                'stream': self.stream_name,
                'messages': stream_info.state.messages,
                'bytes': stream_info.state.bytes,
                'consumers': stream_info.state.consumer_count
            })

        except Exception as e:
            logger.error("Failed to get stream info", extra={
                'error': str(e)
            })

    async def monitor_queue(self):
        """Background task to monitor queue depth"""
        while True:
            try:
                await self.get_stream_info()
                await asyncio.sleep(30)  # Check every 30 seconds
            except Exception as e:
                logger.error("Queue monitoring error", extra={
                    'error': str(e)
                })
                await asyncio.sleep(30)

    async def run(self):
        """Main processor loop"""
        logger.info("Starting Threat Intelligence Processor (Consumer)")

        # Setup tracing
        setup_tracing()

        # Connect to Redis
        if not self.connect_redis():
            logger.error("Cannot start processor without Redis connection")
            return

        # Connect to NATS
        if not await self.connect_nats():
            logger.error("Cannot start processor without NATS connection")
            return

        logger.info("Processor ready to consume messages")

        # Start queue monitoring task
        monitor_task = asyncio.create_task(self.monitor_queue())

        try:
            # Start consuming messages
            await self.consume_messages()
        except KeyboardInterrupt:
            logger.info("Shutting down processor...")
        finally:
            monitor_task.cancel()
            if self.nc:
                await self.nc.close()
            logger.info("Processor shutdown complete")


def main():
    """Main entry point"""
    import threading

    # Start metrics server in separate thread
    metrics_port = int(os.getenv('METRICS_PORT', 8002))
    logger.info(f"Starting metrics server on port {metrics_port}")

    metrics_thread = threading.Thread(
        target=lambda: app.run(host='0.0.0.0', port=metrics_port),
        daemon=True
    )
    metrics_thread.start()

    # Start processor
    processor = ThreatIndicatorProcessor()
    asyncio.run(processor.run())


if __name__ == '__main__':
    main()
