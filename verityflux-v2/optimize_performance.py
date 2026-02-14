#!/usr/bin/env python3
"""
Performance optimization for VerityFlux.

Target: <10ms response time
Current: ~50-100ms

Optimizations:
1. Caching layer (Redis)
2. Parallel detector execution
3. Lazy loading
4. Result caching
"""

import sys
import time
import hashlib
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, '.')

class PerformanceOptimizer:
    """Optimize VerityFlux performance"""
    
    def __init__(self):
        self.cache = {}  # In-memory cache (use Redis in production)
        self.executor = ThreadPoolExecutor(max_workers=20)  # Parallel execution
    
    def cached_evaluation(self, key: str, eval_func, *args):
        """Cache evaluation results"""
        cache_key = hashlib.md5(key.encode()).hexdigest()
        
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        result = eval_func(*args)
        self.cache[cache_key] = result
        return result
    
    def parallel_detectors(self, detectors: List, target: Dict) -> List[Dict]:
        """Run detectors in parallel"""
        futures = {
            self.executor.submit(detector.detect, target): detector 
            for detector in detectors
        }
        
        results = []
        for future in as_completed(futures):
            try:
                result = future.result(timeout=5)  # 5s timeout per detector
                results.append(result)
            except Exception as e:
                print(f"Detector failed: {e}")
        
        return results

# Performance testing
print("="*70)
print("⚡ VERITYFLUX PERFORMANCE OPTIMIZATION")
print("="*70)

from cognitive_firewall import CognitiveFirewall, AgentAction

# Test 1: Baseline performance
print("\n[TEST 1] Baseline Performance")
print("-"*70)

firewall = CognitiveFirewall()

action = AgentAction(
    agent_id="perf_test",
    tool_name="read_file",
    parameters={"path": "/test.txt"},
    reasoning_chain=["Read file"],
    original_goal="Read file",
    context={}
)

# Measure 100 iterations
times = []
for i in range(100):
    start = time.perf_counter()
    decision = firewall.evaluate(action)
    end = time.perf_counter()
    times.append((end - start) * 1000)  # Convert to ms

avg_time = sum(times) / len(times)
min_time = min(times)
max_time = max(times)
p95_time = sorted(times)[int(len(times) * 0.95)]

print(f"Average: {avg_time:.2f}ms")
print(f"Min: {min_time:.2f}ms")
print(f"Max: {max_time:.2f}ms")
print(f"P95: {p95_time:.2f}ms")

if avg_time < 10:
    print("✅ PASS: <10ms target achieved!")
elif avg_time < 50:
    print("⚠️  ACCEPTABLE: 10-50ms (optimization needed)")
else:
    print("❌ FAIL: >50ms (major optimization needed)")

# Test 2: Throughput
print("\n[TEST 2] Throughput Testing")
print("-"*70)

requests = 1000
start = time.perf_counter()

for i in range(requests):
    decision = firewall.evaluate(action)

end = time.perf_counter()
duration = end - start
rps = requests / duration

print(f"Total Time: {duration:.2f}s")
print(f"Requests: {requests}")
print(f"Throughput: {rps:.0f} req/sec")

if rps >= 10000:
    print("✅ EXCELLENT: >10k req/sec")
elif rps >= 1000:
    print("⚠️  GOOD: 1k-10k req/sec")
else:
    print("❌ NEEDS WORK: <1k req/sec")

print("\n" + "="*70)
print("💡 OPTIMIZATION RECOMMENDATIONS")
print("="*70)

if avg_time >= 10:
    print("1. Implement caching layer (Redis)")
    print("2. Use parallel detector execution")
    print("3. Optimize embedding lookups")
    print("4. Add result caching")

if rps < 1000:
    print("5. Add load balancing")
    print("6. Use async processing")
    print("7. Optimize database queries")

print("="*70)

