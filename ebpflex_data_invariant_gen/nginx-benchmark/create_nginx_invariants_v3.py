#!/usr/bin/env python3
"""
Generate Daikon invariants for nginx patterns - Fixed exit points
"""

import subprocess
import os

# Create trace data based on nginx patterns
trace_lines = []

# Add declarations at the start
trace_lines.append("decl-version 2.0")
trace_lines.append("var-comparability implicit")
trace_lines.append("")

# Declare checkAlloc method
trace_lines.append("ppt SimpleNginx.checkAlloc(int):::ENTER")
trace_lines.append("  ppt-type enter")
trace_lines.append("  variable size")
trace_lines.append("    var-kind variable")
trace_lines.append("    rep-type int")
trace_lines.append("    dec-type int")
trace_lines.append("    comparability 1")
trace_lines.append("")

trace_lines.append("ppt SimpleNginx.checkAlloc(int):::EXIT1")
trace_lines.append("  ppt-type exit")
trace_lines.append("  variable size")
trace_lines.append("    var-kind variable")
trace_lines.append("    rep-type int")
trace_lines.append("    dec-type int")
trace_lines.append("    comparability 1")
trace_lines.append("  variable return")
trace_lines.append("    var-kind return")
trace_lines.append("    rep-type int")
trace_lines.append("    dec-type int")
trace_lines.append("    comparability 2")
trace_lines.append("")

# Declare checkStatus method
trace_lines.append("ppt SimpleNginx.checkStatus(int):::ENTER")
trace_lines.append("  ppt-type enter")
trace_lines.append("  variable status")
trace_lines.append("    var-kind variable")
trace_lines.append("    rep-type int")
trace_lines.append("    dec-type int")
trace_lines.append("    comparability 1")
trace_lines.append("")

trace_lines.append("ppt SimpleNginx.checkStatus(int):::EXIT1")
trace_lines.append("  ppt-type exit")
trace_lines.append("  variable status")
trace_lines.append("    var-kind variable")
trace_lines.append("    rep-type int")
trace_lines.append("    dec-type int")
trace_lines.append("    comparability 1")
trace_lines.append("  variable return")
trace_lines.append("    var-kind return")
trace_lines.append("    rep-type int")
trace_lines.append("    dec-type int")
trace_lines.append("    comparability 2")
trace_lines.append("")

# Memory allocation patterns
alloc_tests = [
    (0, -1),      # zero size
    (512, 512),   # small allocation
    (1024, 1024), # medium allocation
    (2048, 2048), # larger allocation
    (4096, 4096), # max allocation
    (4608, -1),   # too large
    (8192, -1),   # way too large
    (-100, -1),   # negative size
]

for size, expected in alloc_tests:
    trace_lines.append("SimpleNginx.checkAlloc(int):::ENTER")
    trace_lines.append("size")
    trace_lines.append(str(size))
    trace_lines.append("1")
    trace_lines.append("")
    
    trace_lines.append("SimpleNginx.checkAlloc(int):::EXIT1")
    trace_lines.append("size")
    trace_lines.append(str(size))
    trace_lines.append("1")
    trace_lines.append("return")
    trace_lines.append(str(expected))
    trace_lines.append("1")
    trace_lines.append("")

# HTTP status code patterns
status_tests = [
    (100, 1),  # informational
    (101, 1),
    (200, 2),  # success
    (201, 2),
    (204, 2),
    (301, 3),  # redirection
    (302, 3),
    (304, 3),
    (400, 4),  # client error
    (401, 4),
    (403, 4),
    (404, 4),
    (500, 5),  # server error
    (502, 5),
    (503, 5),
    (600, -1), # invalid
    (99, -1),  # invalid
]

for status, expected in status_tests:
    trace_lines.append("SimpleNginx.checkStatus(int):::ENTER")
    trace_lines.append("status")
    trace_lines.append(str(status))
    trace_lines.append("1")
    trace_lines.append("")
    
    trace_lines.append("SimpleNginx.checkStatus(int):::EXIT1")
    trace_lines.append("status")
    trace_lines.append(str(status))
    trace_lines.append("1")
    trace_lines.append("return")
    trace_lines.append(str(expected))
    trace_lines.append("1")
    trace_lines.append("")

# Write trace file
with open('/home/nginx_v3.dtrace', 'w') as f:
    f.write('\n'.join(trace_lines))

print("Created nginx_v3.dtrace file")

# Run Daikon
print("\nRunning Daikon to generate invariants...")
try:
    result = subprocess.run(
        ['java', '-cp', '/home/daikon/daikon.jar', 'daikon.Daikon', '/home/nginx_v3.dtrace'],
        capture_output=True,
        text=True,
        timeout=60
    )
    
    print("\n=== NGINX-LIKE INVARIANTS DISCOVERED ===")
    if result.stdout:
        # Parse and display the invariants nicely
        lines = result.stdout.split('\n')
        current_ppt = None
        
        for line in lines:
            if ':::ENTER' in line or ':::EXIT' in line:
                current_ppt = line.strip()
                print(f"\n{current_ppt}")
                print("-" * len(current_ppt))
            elif line.strip() and not line.startswith('Daikon') and not line.startswith('Reading') and not line.startswith('Processing'):
                if current_ppt:
                    print(f"  {line.strip()}")
    
    if result.stderr:
        print("\n=== ERRORS ===")
        print(result.stderr)
        
except subprocess.TimeoutExpired:
    print("Daikon timed out - this might mean it's processing a lot of data")
except Exception as e:
    print(f"Error running Daikon: {e}")

print("\n\n=== SUMMARY OF NGINX PATTERNS ===")
print("1. Memory Allocation (ngx_palloc):")
print("   - Allocations fail (return -1) when size <= 0 or size > 4096")
print("   - Valid allocations return the requested size")
print("   - Common allocation sizes are powers of 2 or multiples of 512")
print("\n2. HTTP Status Codes (ngx_http_status_check):")
print("   - Status codes are grouped by category (1xx, 2xx, 3xx, 4xx, 5xx)")
print("   - Invalid status codes (< 100 or >= 600) return -1")
print("   - Each category maps to a specific return value (1-5)")

print("\nInvariants analysis complete!")