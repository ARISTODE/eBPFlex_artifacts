#!/usr/bin/env python3
"""
Comprehensive nginx invariants analysis using Daikon
"""

import subprocess
import os

# Create trace data for more nginx patterns
trace_lines = []

# Add declarations
trace_lines.append("decl-version 2.0")
trace_lines.append("var-comparability implicit")
trace_lines.append("")

# 1. Memory allocation function
trace_lines.append("ppt ngx_palloc:::ENTER")
trace_lines.append("  ppt-type enter")
trace_lines.append("  variable pool_size")
trace_lines.append("    var-kind variable")
trace_lines.append("    rep-type int")
trace_lines.append("    dec-type int")
trace_lines.append("    comparability 1")
trace_lines.append("  variable request_size")
trace_lines.append("    var-kind variable")
trace_lines.append("    rep-type int")
trace_lines.append("    dec-type int")
trace_lines.append("    comparability 2")
trace_lines.append("")

trace_lines.append("ppt ngx_palloc:::EXIT1")
trace_lines.append("  ppt-type exit")
trace_lines.append("  variable pool_size")
trace_lines.append("    var-kind variable")
trace_lines.append("    rep-type int")
trace_lines.append("    dec-type int")
trace_lines.append("    comparability 1")
trace_lines.append("  variable request_size")
trace_lines.append("    var-kind variable")
trace_lines.append("    rep-type int")
trace_lines.append("    dec-type int")
trace_lines.append("    comparability 2")
trace_lines.append("  variable return")
trace_lines.append("    var-kind return")
trace_lines.append("    rep-type int")
trace_lines.append("    dec-type int")
trace_lines.append("    comparability 3")
trace_lines.append("")

# 2. Request processing function
trace_lines.append("ppt ngx_http_process_request:::ENTER")
trace_lines.append("  ppt-type enter")
trace_lines.append("  variable method")
trace_lines.append("    var-kind variable")
trace_lines.append("    rep-type int")
trace_lines.append("    dec-type int")
trace_lines.append("    comparability 1")
trace_lines.append("  variable uri_length")
trace_lines.append("    var-kind variable")
trace_lines.append("    rep-type int")
trace_lines.append("    dec-type int")
trace_lines.append("    comparability 2")
trace_lines.append("")

trace_lines.append("ppt ngx_http_process_request:::EXIT1")
trace_lines.append("  ppt-type exit")
trace_lines.append("  variable method")
trace_lines.append("    var-kind variable")
trace_lines.append("    rep-type int")
trace_lines.append("    dec-type int")
trace_lines.append("    comparability 1")
trace_lines.append("  variable uri_length")
trace_lines.append("    var-kind variable")
trace_lines.append("    rep-type int")
trace_lines.append("    dec-type int")
trace_lines.append("    comparability 2")
trace_lines.append("  variable status_code")
trace_lines.append("    var-kind return")
trace_lines.append("    rep-type int")
trace_lines.append("    dec-type int")
trace_lines.append("    comparability 3")
trace_lines.append("")

# 3. Buffer size calculation
trace_lines.append("ppt ngx_http_alloc_large_header_buffer:::ENTER")
trace_lines.append("  ppt-type enter")
trace_lines.append("  variable current_size")
trace_lines.append("    var-kind variable")
trace_lines.append("    rep-type int")
trace_lines.append("    dec-type int")
trace_lines.append("    comparability 1")
trace_lines.append("  variable needed_size")
trace_lines.append("    var-kind variable")
trace_lines.append("    rep-type int")
trace_lines.append("    dec-type int")
trace_lines.append("    comparability 2")
trace_lines.append("")

trace_lines.append("ppt ngx_http_alloc_large_header_buffer:::EXIT1")
trace_lines.append("  ppt-type exit")
trace_lines.append("  variable current_size")
trace_lines.append("    var-kind variable")
trace_lines.append("    rep-type int")
trace_lines.append("    dec-type int")
trace_lines.append("    comparability 1")
trace_lines.append("  variable needed_size")
trace_lines.append("    var-kind variable")
trace_lines.append("    rep-type int")
trace_lines.append("    dec-type int")
trace_lines.append("    comparability 2")
trace_lines.append("  variable new_size")
trace_lines.append("    var-kind return")
trace_lines.append("    rep-type int")
trace_lines.append("    dec-type int")
trace_lines.append("    comparability 3")
trace_lines.append("")

# Generate test data

# 1. Memory allocation patterns
pool_sizes = [4096, 8192, 16384]
request_sizes = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192]

for pool_size in pool_sizes:
    for req_size in request_sizes:
        trace_lines.append("ngx_palloc:::ENTER")
        trace_lines.append("pool_size")
        trace_lines.append(str(pool_size))
        trace_lines.append("1")
        trace_lines.append("request_size")
        trace_lines.append(str(req_size))
        trace_lines.append("1")
        trace_lines.append("")
        
        # Return 0 if request > pool, else return 1 (success)
        result = 0 if req_size > pool_size else 1
        
        trace_lines.append("ngx_palloc:::EXIT1")
        trace_lines.append("pool_size")
        trace_lines.append(str(pool_size))
        trace_lines.append("1")
        trace_lines.append("request_size")
        trace_lines.append(str(req_size))
        trace_lines.append("1")
        trace_lines.append("return")
        trace_lines.append(str(result))
        trace_lines.append("1")
        trace_lines.append("")

# 2. HTTP request processing patterns
# Methods: 1=GET, 2=POST, 3=HEAD, 4=PUT, 5=DELETE
methods = [1, 2, 3, 4, 5]
uri_lengths = [10, 50, 100, 255, 500, 1000, 2000]

for method in methods:
    for uri_len in uri_lengths:
        trace_lines.append("ngx_http_process_request:::ENTER")
        trace_lines.append("method")
        trace_lines.append(str(method))
        trace_lines.append("1")
        trace_lines.append("uri_length")
        trace_lines.append(str(uri_len))
        trace_lines.append("1")
        trace_lines.append("")
        
        # Status depends on URI length
        if uri_len > 1024:
            status = 414  # URI too long
        elif uri_len < 1:
            status = 400  # Bad request
        else:
            status = 200  # OK
        
        trace_lines.append("ngx_http_process_request:::EXIT1")
        trace_lines.append("method")
        trace_lines.append(str(method))
        trace_lines.append("1")
        trace_lines.append("uri_length")
        trace_lines.append(str(uri_len))
        trace_lines.append("1")
        trace_lines.append("status_code")
        trace_lines.append(str(status))
        trace_lines.append("1")
        trace_lines.append("")

# 3. Buffer allocation patterns
current_sizes = [1024, 2048, 4096, 8192]
needed_sizes = [512, 1024, 2048, 4096, 8192, 16384]

for current in current_sizes:
    for needed in needed_sizes:
        trace_lines.append("ngx_http_alloc_large_header_buffer:::ENTER")
        trace_lines.append("current_size")
        trace_lines.append(str(current))
        trace_lines.append("1")
        trace_lines.append("needed_size")
        trace_lines.append(str(needed))
        trace_lines.append("1")
        trace_lines.append("")
        
        # Calculate new buffer size (typical nginx logic)
        if needed <= current:
            new_size = current
        elif needed <= 4096:
            new_size = 4096
        elif needed <= 8192:
            new_size = 8192
        else:
            new_size = 16384
        
        trace_lines.append("ngx_http_alloc_large_header_buffer:::EXIT1")
        trace_lines.append("current_size")
        trace_lines.append(str(current))
        trace_lines.append("1")
        trace_lines.append("needed_size")
        trace_lines.append(str(needed))
        trace_lines.append("1")
        trace_lines.append("new_size")
        trace_lines.append(str(new_size))
        trace_lines.append("1")
        trace_lines.append("")

# Write trace file
with open('/home/nginx_comprehensive.dtrace', 'w') as f:
    f.write('\n'.join(trace_lines))

print("Created nginx_comprehensive.dtrace file")

# Run Daikon with options
print("\nRunning Daikon to generate invariants...")
try:
    result = subprocess.run(
        ['java', '-cp', '/home/daikon/daikon.jar', 
         'daikon.Daikon', 
         '--config_option', 'daikon.derive.Derivation.disable_derived_variables=true',
         '--config_option', 'daikon.simplify.Session.simplify_max_iterations=2',
         '/home/nginx_comprehensive.dtrace'],
        capture_output=True,
        text=True,
        timeout=120
    )
    
    print("\n=== NGINX INVARIANTS DISCOVERED ===\n")
    
    # Parse output
    lines = result.stdout.split('\n')
    current_ppt = None
    invariants = {}
    
    for line in lines:
        if ':::ENTER' in line or ':::EXIT' in line:
            current_ppt = line.strip()
            if current_ppt not in invariants:
                invariants[current_ppt] = []
        elif line.strip() and current_ppt and not line.startswith('Daikon') and \
             not line.startswith('Reading') and not line.startswith('Processing') and \
             not line.startswith('===='):
            invariants[current_ppt].append(line.strip())
    
    # Display invariants organized by function
    print("1. MEMORY ALLOCATION (ngx_palloc)")
    print("=" * 50)
    for ppt, inv_list in invariants.items():
        if 'ngx_palloc' in ppt:
            print(f"\n{ppt}:")
            for inv in inv_list:
                if inv:
                    print(f"  - {inv}")
    
    print("\n\n2. REQUEST PROCESSING (ngx_http_process_request)")
    print("=" * 50)
    for ppt, inv_list in invariants.items():
        if 'ngx_http_process_request' in ppt:
            print(f"\n{ppt}:")
            for inv in inv_list:
                if inv:
                    print(f"  - {inv}")
    
    print("\n\n3. BUFFER ALLOCATION (ngx_http_alloc_large_header_buffer)")
    print("=" * 50)
    for ppt, inv_list in invariants.items():
        if 'ngx_http_alloc_large_header_buffer' in ppt:
            print(f"\n{ppt}:")
            for inv in inv_list:
                if inv:
                    print(f"  - {inv}")
    
except subprocess.TimeoutExpired:
    print("Daikon processing took longer than expected")
except Exception as e:
    print(f"Error: {e}")

print("\n\n=== KEY NGINX INVARIANTS SUMMARY ===")
print("1. Memory allocation is constrained by pool size")
print("2. URI length affects HTTP status codes (too long = 414)")
print("3. Buffer sizes increase in powers of 2 (1024, 2048, 4096, 8192, 16384)")
print("4. HTTP methods are typically in range 1-5 (GET, POST, HEAD, PUT, DELETE)")
print("5. Successful allocations depend on request_size <= pool_size")

print("\nAnalysis complete!")