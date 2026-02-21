"""
Performance tests for SOC Firewall
Measures throughput, latency, and resource usage
"""

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
        print(f"  CPU: {metrics.cpu_percent:.1f}%")
        print(f"  Memory: {metrics.memory_mb:.1f} MB")
    
    def test_ids_detection_latency(self):
        """Test IDS detection latency"""
        
        engine = IDSEngine()
        
        class MockMetadata:
            def __init__(self):
                self.protocol = "TCP"
                self.src_ip = "192.168.1.100"
                self.dst_ip = "10.0.0.1"
                self.dst_port = 80
                self.flags = []
                self.packet_size = 200
        
        metadata = MockMetadata()
        
        # Test payloads
        test_payloads = [
            b"GET /page.php?id=1 UNION SELECT * FROM users --",
            b"<script>alert('XSS')</script>",
            b"../../../etc/passwd",
            b"normal HTTP request",
            b"POST /login.php user=admin&pass=12345",
            b"GET /index.html HTTP/1.1"
        ]
        
        latencies = []
        detections = 0
        
        for payload in test_payloads:
            start = time.time()
            result = engine.inspect_packet(metadata, payload)
            latency = (time.time() - start) * 1000  # ms
            latencies.append(latency)
            
            if result.detected:
                detections += 1
        
        avg_latency = sum(latencies) / len(latencies)
        detection_rate = detections / len(test_payloads)
        
        assert avg_latency < 5.0, f"IDS latency too high: {avg_latency:.2f} ms"
        assert detection_rate > 0.3, f"Detection rate too low: {detection_rate:.2f}"
        
        print(f"\nIDS Performance:")
        print(f"  Avg Latency: {avg_latency:.3f} ms")
        print(f"  Detection Rate: {detection_rate:.2f}")
        print(f"  Max Latency: {max(latencies):.3f} ms")
    
    def test_concurrent_connection_handling(self):
        """Test handling of many concurrent connections"""
        
        from src.core.connection_tracker import ConnectionTracker
        
        tracker = ConnectionTracker(max_connections=100000)
        
        class MockMetadata:
            def __init__(self, src_ip, dst_ip, src_port, dst_port):
                self.protocol = "TCP"
                self.src_ip = src_ip
                self.dst_ip = dst_ip
                self.src_port = src_port
                self.dst_port = dst_port
                self.flags = ["SYN"]
                self.packet_size = 64
        
        # Create many connections
        num_connections = 10000
        start_time = time.time()
        
        for i in range(num_connections):
            src_ip = f"192.168.1.{i % 254}"
            dst_ip = f"10.0.0.{i % 100}"
            src_port = 10000 + i
            dst_port = 80
            
            packet = MockMetadata(src_ip, dst_ip, src_port, dst_port)
            tracker.get_or_create_connection(packet)
        
        elapsed = time.time() - start_time
        connections_per_second = num_connections / elapsed
        
        # Check final count
        final_count = tracker.get_connection_count()
        
        assert final_count == num_connections
        assert connections_per_second > 5000, f"Connection creation rate too low: {connections_per_second:.0f}/s"
        
        print(f"\nConnection Tracking:")
        print(f"  Connections: {final_count}")
        print(f"  Creation Rate: {connections_per_second:.0f}/s")
        print(f"  Memory per connection: {tracker.get_statistics()['utilization_percent']:.1f}%")
    
    def test_memory_usage_under_load(self):
        """Test memory usage under sustained load"""
        
        import psutil
        process = psutil.Process()
        
        from src.core.packet_engine import PacketProcessor
        
        processor = PacketProcessor(interface="lo")
        
        # Generate packets
        from scapy.all import IP, TCP, Ether
        
        memory_samples = []
        
        for batch in range(10):
            # Process batch of packets
            for i in range(1000):
                pkt = Ether()/IP(src=f"192.168.1.{i%254}", dst="10.0.0.1")/TCP(sport=12345, dport=80)
                processor.packet_callback(pkt)
            
            # Allow processing
            time.sleep(0.1)
            
            # Sample memory
            memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_samples.append(memory)
        
        # Check for memory leaks (should not grow significantly)
        initial_memory = memory_samples[0]
        final_memory = memory_samples[-1]
        memory_growth = final_memory - initial_memory
        
        assert memory_growth < 50, f"Possible memory leak: grew {memory_growth:.1f} MB"
        
        print(f"\nMemory Usage:")
        print(f"  Initial: {initial_memory:.1f} MB")
        print(f"  Final: {final_memory:.1f} MB")
        print(f"  Growth: {memory_growth:.1f} MB")
