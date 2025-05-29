#!/usr/bin/env python3
"""
Generate Daikon invariants for nginx patterns
"""

import subprocess
import os

# Create a simple declaration and trace file
decls_content = """decl-version 2.0
var-comparability implicit

ppt SimpleNginx.checkAlloc(int):::ENTER
  ppt-type enter
  variable size
    var-kind variable
    rep-type int
    dec-type int
    comparability 1

ppt SimpleNginx.checkAlloc(int):::EXIT
  ppt-type exit
  variable size
    var-kind variable
    rep-type int
    dec-type int
    comparability 1
  variable return
    var-kind return
    rep-type int
    dec-type int
    comparability 2

ppt SimpleNginx.checkStatus(int):::ENTER
  ppt-type enter
  variable status
    var-kind variable
    rep-type int
    dec-type int
    comparability 1

ppt SimpleNginx.checkStatus(int):::EXIT
  ppt-type exit
  variable status
    var-kind variable
    rep-type int
    dec-type int
    comparability 1
  variable return
    var-kind return
    rep-type int
    dec-type int
    comparability 2
"""

# Create trace data based on nginx patterns
trace_data = []

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
    trace_data.append(f"SimpleNginx.checkAlloc(int):::ENTER\nsize\n{size}\n1\n")
    trace_data.append(f"SimpleNginx.checkAlloc(int):::EXIT\nsize\n{size}\nreturn\n{expected}\n1\n")

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
    trace_data.append(f"SimpleNginx.checkStatus(int):::ENTER\nstatus\n{status}\n1\n")
    trace_data.append(f"SimpleNginx.checkStatus(int):::EXIT\nstatus\n{status}\nreturn\n{expected}\n1\n")

# Write declarations file
with open('/home/nginx.decls', 'w') as f:
    f.write(decls_content)

# Write trace file
with open('/home/nginx.dtrace', 'w') as f:
    f.write(decls_content + '\n')
    f.write('\n'.join(trace_data))

print("Created nginx.decls and nginx.dtrace files")

# Run Daikon
print("\nRunning Daikon to generate invariants...")
try:
    result = subprocess.run(
        ['java', '-cp', '/home/daikon/daikon.jar', 'daikon.Daikon', '/home/nginx.dtrace'],
        capture_output=True,
        text=True
    )
    
    print("\n=== DAIKON OUTPUT ===")
    print(result.stdout)
    
    if result.stderr:
        print("\n=== ERRORS ===")
        print(result.stderr)
        
except Exception as e:
    print(f"Error running Daikon: {e}")

print("\nInvariants analysis complete!")