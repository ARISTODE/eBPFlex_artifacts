#!/bin/bash

# Example script to demonstrate eBPFlex usage with all security policies

echo "=== eBPFlex Example: Generating eBPF programs with SP1-SP4 policies ==="

# Set paths
PDG_DIR="../program-dependence-graph"
BUILD_DIR="$PDG_DIR/build"
INVARIANT_FILE="../ebpflex_data_invariant_gen/nginx-benchmark/nginx_v3_invariants.txt"
PROTOCOL_FILE="protocol_specs/nginx_pcre.protocol"
INTERFACE_FUNCS="nginx_interface_funcs.txt"

# Create interface functions file
cat > $INTERFACE_FUNCS << EOF
pcre2_compile
pcre2_match
pcre2_code_free
EOF

# Step 1: Build the PDG tool if not already built
if [ ! -d "$BUILD_DIR" ]; then
    echo "Building PDG tool..."
    mkdir -p $BUILD_DIR
    cd $BUILD_DIR
    cmake ..
    make -j$(nproc)
    cd -
fi

# Step 2: Run the eBPF generation with all policies enabled
echo "Generating eBPF program with all security policies..."
cd nginx_example

# Run the PDG analysis and eBPF generation
opt -load $BUILD_DIR/lib/pdg.so \
    -ebpf-gen \
    -ifuncs=$INTERFACE_FUNCS \
    -invariants=$INVARIANT_FILE \
    -protocol=$PROTOCOL_FILE \
    -binpath=/usr/local/nginx/sbin/nginx \
    < nginx.bc \
    -o /dev/null

echo "=== Generated eBPF program ==="
echo "Generated files:"
echo "  - prog.ebpf.c : eBPF kernel program with SP1-SP4 enforcement"
echo "  - prog.py     : Python userspace loader"

# Show a snippet of the generated eBPF program
echo ""
echo "=== Sample of generated eBPF code with security policies ==="
head -100 prog.ebpf.c | grep -E "(SP1:|SP2:|SP3:|SP4:|Check:|Masking|Protocol|Invariant)" || echo "Run the full example to see policy enforcement code"

echo ""
echo "=== Security Policies Implemented ==="
echo "SP1 (Read Access Control): Non-readable fields are masked/zeroed before untrusted access"
echo "SP2 (Write Access Control): Read-only fields are monitored for unauthorized modifications"  
echo "SP3 (Data Validation): Data invariants from Daikon are enforced at runtime"
echo "SP4 (Protocol Enforcement): Function call sequences are validated against FSM specification"

echo ""
echo "To run the eBPF program:"
echo "  sudo python3 prog.py"