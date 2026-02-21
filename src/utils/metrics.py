import time
import threading
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime
import json
from pathlib import Path

from src.utils.logger import get_logger

logger = get_logger(__name__)


class MetricType(Enum):
    """Types of metrics"""
    COUNTER = "counter"      # Monotonically increasing counter
    GAUGE = "gauge"          # Snapshot value
    HISTOGRAM = "histogram"   # Distribution of values
    TIMER = "timer"           # Duration measurements
    RATE = "rate"            # Rate of events per second


@dataclass
class Metric:
    """Metric data point"""
    name: str
    type: MetricType
    value: float
    timestamp: float
    tags: Dict[str, str] = field(default_factory=dict)
    labels: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'name': self.name,
            'type': self.type.value,
            'value': self.value,
            'timestamp': self.timestamp,
            'tags': self.tags,
            'labels': self.labels
        }


class MetricsRegistry:
    """
    Registry for storing and managing metrics
    """
    
    def __init__(self):
        self.metrics: Dict[str, List[Metric]] = defaultdict(list)
        self.counters: Dict[str, float] = {}
        self.gauges: Dict[str, float] = {}
        self.histograms: Dict[str, List[float]] = defaultdict(list)
        self.timers: Dict[str, List[float]] = defaultdict(list)
        self.lock = threading.RLock()
    
    def record(self, metric: Metric) -> None:
        """Record a metric"""
        with self.lock:
            self.metrics[metric.name].append(metric)
            
            # Keep only last 1000 metrics per name
            if len(self.metrics[metric.name]) > 1000:
                self.metrics[metric.name] = self.metrics[metric.name][-1000:]
            
            # Update type-specific storage
            if metric.type == MetricType.COUNTER:
                self.counters[metric.name] = metric.value
            elif metric.type == MetricType.GAUGE:
                self.gauges[metric.name] = metric.value
            elif metric.type == MetricType.HISTOGRAM:
                self.histograms[metric.name].append(metric.value)
                # Keep last 1000
                if len(self.histograms[metric.name]) > 1000:
                    self.histograms[metric.name] = self.histograms[metric.name][-1000:]
            elif metric.type == MetricType.TIMER:
                self.timers[metric.name].append(metric.value)
                if len(self.timers[metric.name]) > 1000:
                    self.timers[metric.name] = self.timers[metric.name][-1000:]
    
    def get_counter(self, name: str) -> Optional[float]:
        """Get current counter value"""
        with self.lock:
            return self.counters.get(name)
    
    def get_gauge(self, name: str) -> Optional[float]:
        """Get current gauge value"""
        with self.lock:
            return self.gauges.get(name)
    
    def get_histogram_stats(self, name: str) -> Optional[Dict]:
        """Get histogram statistics"""
        with self.lock:
            values = self.histograms.get(name)
            if not values:
                return None
            
            values.sort()
            count = len(values)
            
            return {
                'count': count,
                'min': values[0],
                'max': values[-1],
                'mean': sum(values) / count,
                'median': values[count // 2],
                'p95': values[int(count * 0.95)],
                'p99': values[int(count * 0.99)]
            }
    
    def get_timer_stats(self, name: str) -> Optional[Dict]:
        """Get timer statistics"""
        return self.get_histogram_stats(name)
    
    def get_all_metrics(self) -> Dict:
        """Get all current metrics"""
        with self.lock:
            result = {
                'counters': dict(self.counters),
                'gauges': dict(self.gauges),
                'histograms': {}
            }
            
            for name in self.histograms:
                result['histograms'][name] = self.get_histogram_stats(name)
            
            for name in self.timers:
                result['timers'][name] = self.get_timer_stats(name)
            
            return result
    
    def clear(self) -> None:
        """Clear all metrics"""
        with self.lock:
            self.metrics.clear()
            self.counters.clear()
            self.gauges.clear()
            self.histograms.clear()
            self.timers.clear()


class MetricsCollector:
    """
    Metrics collection and reporting system
    
    Features:
    - Multiple metric types (counter, gauge, histogram, timer)
    - Tagging and labeling
    - Periodic reporting
    - Export in multiple formats
    """
    
    def __init__(self, registry: Optional[MetricsRegistry] = None, 
                 report_interval: int = 60):
        """
        Initialize metrics collector
        
        Args:
            registry: Metrics registry instance
            report_interval: Seconds between automatic reports
        """
        self.registry = registry or MetricsRegistry()
        self.report_interval = report_interval
        self.handlers: List[Callable] = []
        self.running = False
        self.lock = threading.RLock()
        
        # Start reporter thread
        self._start_reporter()
        
        logger.info("Metrics collector initialized")
    
    def _start_reporter(self) -> None:
        """Start background reporter thread"""
        self.running = True
        self.reporter_thread = threading.Thread(
            target=self._reporter_loop,
            daemon=True,
            name="MetricsReporter"
        )
        self.reporter_thread.start()
    
    def _reporter_loop(self) -> None:
        """Periodic reporting loop"""
        while self.running:
            time.sleep(self.report_interval)
            self.report()
    
    def increment(self, name: str, value: float = 1.0, 
                  tags: Optional[Dict[str, str]] = None) -> None:
        """
        Increment a counter metric
        
        Args:
            name: Metric name
            value: Increment value
            tags: Metric tags
        """
        current = self.registry.get_counter(name) or 0
        new_value = current + value
        
        metric = Metric(
            name=name,
            type=MetricType.COUNTER,
            value=new_value,
            timestamp=time.time(),
            tags=tags or {}
        )
        
        self.registry.record(metric)
    
    def gauge(self, name: str, value: float, 
              tags: Optional[Dict[str, str]] = None) -> None:
        """
        Record a gauge metric
        
        Args:
            name: Metric name
            value: Current value
            tags: Metric tags
        """
        metric = Metric(
            name=name,
            type=MetricType.GAUGE,
            value=value,
            timestamp=time.time(),
            tags=tags or {}
        )
        
        self.registry.record(metric)
    
    def histogram(self, name: str, value: float,
                  tags: Optional[Dict[str, str]] = None) -> None:
        """
        Record a histogram metric
        
        Args:
            name: Metric name
            value: Value to add to histogram
            tags: Metric tags
        """
        metric = Metric(
            name=name,
            type=MetricType.HISTOGRAM,
            value=value,
            timestamp=time.time(),
            tags=tags or {}
        )
        
        self.registry.record(metric)
    
    def timer(self, name: str, duration: float,
              tags: Optional[Dict[str, str]] = None) -> None:
        """
        Record a timer metric
        
        Args:
            name: Metric name
            duration: Duration in seconds
            tags: Metric tags
        """
        metric = Metric(
            name=name,
            type=MetricType.TIMER,
            value=duration,
            timestamp=time.time(),
            tags=tags or {}
        )
        
        self.registry.record(metric)
    
    def time(self, name: str, tags: Optional[Dict[str, str]] = None):
        """
        Context manager for timing operations
        
        Args:
            name: Metric name
            tags: Metric tags
        
        Usage:
            with metrics.time('operation_time'):
                do_something()
        """
        return _TimerContext(self, name, tags)
    
    def rate(self, name: str, count: int = 1,
             tags: Optional[Dict[str, str]] = None) -> None:
        """
        Record a rate metric (events per second)
        
        Args:
            name: Metric name
            count: Number of events
            tags: Metric tags
        """
        # Rate is calculated by external system
        metric = Metric(
            name=name,
            type=MetricType.RATE,
            value=count,
            timestamp=time.time(),
            tags=tags or {}
        )
        
        self.registry.record(metric)
    
    def register_handler(self, handler: Callable) -> None:
        """
        Register a metrics handler
        
        Args:
            handler: Handler function that takes metrics dict
        """
        with self.lock:
            self.handlers.append(handler)
    
    def report(self) -> None:
        """Report current metrics to all handlers"""
        metrics = self.registry.get_all_metrics()
        
        with self.lock:
            for handler in self.handlers:
                try:
                    handler(metrics)
                except Exception as e:
                    logger.error(f"Error in metrics handler: {e}")
        
        logger.debug(f"Metrics reported: {len(metrics['counters'])} counters")
    
    def stop(self) -> None:
        """Stop the metrics collector"""
        self.running = False
        if hasattr(self, 'reporter_thread'):
            self.reporter_thread.join(timeout=5)
        logger.info("Metrics collector stopped")


class _TimerContext:
    """Context manager for timing operations"""
    
    def __init__(self, collector: MetricsCollector, name: str,
                 tags: Optional[Dict[str, str]] = None):
        self.collector = collector
        self.name = name
        self.tags = tags
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        self.collector.timer(self.name, duration, self.tags)


class PrometheusExporter:
    """
    Export metrics in Prometheus format
    """
    
    def __init__(self, collector: MetricsCollector):
        """
        Initialize Prometheus exporter
        
        Args:
            collector: Metrics collector instance
        """
        self.collector = collector
        collector.register_handler(self.export)
    
    def export(self, metrics: Dict) -> str:
        """
        Export metrics in Prometheus format
        
        Args:
            metrics: Metrics dictionary
            
        Returns:
            Prometheus formatted string
        """
        lines = []
        
        # Counters
        for name, value in metrics.get('counters', {}).items():
            lines.append(f"# TYPE {name} counter")
            lines.append(f"{name} {value}")
        
        # Gauges
        for name, value in metrics.get('gauges', {}).items():
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name} {value}")
        
        # Histograms
        for name, stats in metrics.get('histograms', {}).items():
            if stats:
                lines.append(f"# TYPE {name} histogram")
                lines.append(f"{name}_count {stats['count']}")
                lines.append(f"{name}_sum {stats['mean'] * stats['count']}")
                lines.append(f"{name}_min {stats['min']}")
                lines.append(f"{name}_max {stats['max']}")
                lines.append(f"{name}_p95 {stats['p95']}")
                lines.append(f"{name}_p99 {stats['p99']}")
        
        return "\n".join(lines)


class JSONExporter:
    """
    Export metrics in JSON format
    """
    
    def __init__(self, collector: MetricsCollector, output_file: Optional[str] = None):
        """
        Initialize JSON exporter
        
        Args:
            collector: Metrics collector instance
            output_file: Optional output file path
        """
        self.collector = collector
        self.output_file = output_file
        collector.register_handler(self.export)
    
    def export(self, metrics: Dict) -> None:
        """
        Export metrics as JSON
        
        Args:
            metrics: Metrics dictionary
        """
        if self.output_file:
            with open(self.output_file, 'w') as f:
                json.dump(metrics, f, indent=2)
        
        # Also return for API usage
        return metrics


# Global metrics collector instance
_metrics_collector = None


def get_metrics_collector() -> MetricsCollector:
    """Get or create global metrics collector"""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
    return _metrics_collector
