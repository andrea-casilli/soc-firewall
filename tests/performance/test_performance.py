import pytest
import time
import psutil
import threading
from typing import List, Dict
from dataclasses import dataclass

from src.core.packet_engine import PacketProcessor
from src.detection.ids_engine import IDSEngine


@dataclass
class PerformanceMetrics:
    """Performance test metrics"""
    packets_per_second: float
    avg_latency_ms: float
    cpu_percent: float
    memory_mb: float
    detection_rate: float


class TestPerformance:
    """Performance tests for firewall components"""
    
    @pytest.fixture
    def metrics_collector(self):
        """Collect system metrics during test"""
        process = psutil.Process()
        metrics = []
        
        def collect():
            while True:
                cpu = process.cpu_percent(interval=0.1)
                mem = process.memory_info().rss / 1024 / 1024  # MB
                metrics.append((cpu, mem))
                time.sleep(0.1)
        
        collector = threading.Thread(target=collect, daemon=True)
        collector.start()
        
        yield metrics
        # Collector will be stopped by daemon thread
    
    def test_packet_processing_throughput(self, metrics_collector):
        """Test maximum packet processing throughput"""
        
        # Create packet processor with minimal workers for consistent testing
        processor = PacketProcessor(interface="lo")
        processor.num_workers = 2
        
        # Generate synthetic packets
        from scapy.all import IP, TCP, Ether
        
        packets = []
        for i in range(10000):
            pkt = Ether()/IP(src=f"192.168.1.{i%254}", dst="10.0.0.1")/TCP(sport=12345, dport=80)
            packets.append(pkt)
        
        # Measure processing time
        start_time = time.time()
        
        for pkt in packets:
            processor.packet_callback(pkt)
        
        # Wait for processing
        time.sleep(1)
        
        end_time = time.time()
        
        # Calculate metrics
        elapsed = end_time - start_time
        packets_per_second = len(packets) / elapsed
        
        # Get average CPU and memory
        if metrics_collector:
            avg_cpu = sum(m[0] for m in metrics_collector) / len(metrics_collector) if metrics_collector else 0
            avg_mem = sum(m[1] for m in metrics_collector) / len(metrics_collector) if metrics_collector else 0
        else:
            avg_cpu = 0
            avg_mem = 0
        
        metrics = PerformanceMetrics(
            packets_per_second=packets_per_second,
            avg_latency_ms=(elapsed / len(packets)) * 1000,
            cpu_percent=avg_cpu,
            memory_mb=avg_mem,
            detection_rate=0
        )
        
        # Assert minimum performance
        assert metrics.packets_per_second > 1000, f"Throughput too low: {metrics.packets_per_second} pps"
        assert metrics.avg_latency_ms < 1.0, f"Latency too high: {metrics.avg_latency_ms} ms"
        
        print(f"\nPerformance Results:")
        print(f"  Packets/second: {metrics.packets_per_second:.2f}")
        print(f"  Avg Latency: {metrics.avg_latency_ms:.3f} ms")
        print(f"  CPU: {metrics.cpu_per
