# eBPFlex Implementation Documentation

## Overview

This implementation provides a complete eBPFlex system that automatically generates eBPF programs to enforce security policies (SP1-SP4) for compartmentalized applications. The system mitigates Cross-Compartment Interface Vulnerabilities (CIVs) by enforcing access control, data validation, and protocol compliance at runtime.

## Security Policies Implemented

### SP1: Read Access Control (Data Leakage Prevention)
- **Implementation**: `eBPFProgGeneration.cpp:725-759`
- **Features**:
  - Automatically masks non-readable fields before untrusted access
  - Zeros out sensitive data fields
  - Restores original values after function returns
  - Prevents pointer leakage by setting non-readable pointers to NULL

### SP2: Write Access Control (Data Corruption Prevention)
- **Implementation**: `eBPFProgGeneration.cpp:875-894`
- **Features**:
  - Monitors read-only fields for unauthorized modifications
  - Detects illegal updates at function exit
  - Reports violations via eBPF trace output
  - Currently implements post-facto detection (enhancement for real-time prevention pending)

### SP3: Data Validation (Invariant Enforcement)
- **Implementation**: `InvariantConverter.cpp`
- **Features**:
  - Converts Daikon-generated invariants to eBPF checks
  - Supports multiple invariant types:
    - Equality constraints (e.g., `field == value`)
    - Comparison constraints (e.g., `field > value`)
    - Null pointer checks
    - Range/set membership checks
    - Power-of-two constraints
  - Enforces invariants at function entry/exit
  - Blocks execution on invariant violations

### SP4: Interface Protocol Enforcement
- **Implementation**: `ProtocolInference.cpp`
- **Features**:
  - Enforces valid function call sequences using FSM
  - Tracks per-process protocol state
  - Validates state transitions on function entry
  - Supports protocol specification files
  - Can infer protocols from execution traces
  - Blocks invalid function calls that violate protocol

## Directory Structure

```
eBPFlex_artifacts/
├── program-dependence-graph/       # Core PDG and eBPF generation
│   ├── include/
│   │   ├── eBPFProgGeneration.hpp  # Main eBPF generator header
│   │   ├── InvariantConverter.hh   # SP3 invariant conversion
│   │   └── ProtocolInference.hh    # SP4 protocol enforcement
│   ├── src/
│   │   ├── eBPFProgGeneration.cpp  # SP1/SP2 implementation
│   │   ├── InvariantConverter.cpp  # SP3 implementation
│   │   └── ProtocolInference.cpp   # SP4 implementation
│   └── CMakeLists.txt
├── ebpflex_data_invariant_gen/     # Data invariants from Daikon
│   ├── nginx-benchmark/            # Nginx invariants
│   ├── memcached-benchmark/        # Memcached invariants
│   ├── ffmpeg-benchmark/           # FFmpeg invariants
│   └── rsync-benchmark/            # Rsync invariants
└── examples/                       # Usage examples
    ├── protocol_specs/             # Protocol specifications
    └── run_ebpflex_example.sh      # Example usage script
```

## Building the System

```bash
cd program-dependence-graph
mkdir build && cd build
cmake ..
make -j$(nproc)
```

## Usage

### Basic Usage
```bash
opt -load path/to/pdg.so -ebpf-gen \
    -ifuncs=interface_functions.txt \
    < input.bc -o /dev/null
```

### With All Security Policies
```bash
opt -load path/to/pdg.so -ebpf-gen \
    -ifuncs=interface_functions.txt \
    -invariants=invariants.txt \
    -protocol=protocol.spec \
    -binpath=/path/to/binary \
    < input.bc -o /dev/null
```

### Command Line Options
- `-ifuncs`: File containing interface function names (one per line)
- `-invariants`: Daikon invariant file for SP3 enforcement
- `-protocol`: Protocol specification file for SP4 enforcement
- `-binpath`: Path to the target binary for instrumentation

## Generated Output

The system generates two files:

1. **prog.ebpf.c**: eBPF kernel program containing:
   - Entry/exit probes for interface functions
   - SP1 field masking code
   - SP2 write access checks
   - SP3 invariant validation
   - SP4 protocol state tracking

2. **prog.py**: Python userspace loader using BCC

## Protocol Specification Format

```
PROTOCOL protocol_name
STATE state_name [initial] [final]
TRANSITION from_state to_state function_name [condition]
```

Example:
```
PROTOCOL lock_protocol
STATE UNLOCKED initial final
STATE LOCKED
TRANSITION UNLOCKED LOCKED acquire_lock
TRANSITION LOCKED UNLOCKED release_lock
```

## Invariant File Format

Daikon output format with program points:
```
function_name:::ENTER
variable == value
variable > value
...

function_name:::EXIT
postcondition invariants
...
```

## Testing

Test programs are provided for each application:
- FFmpeg: `ffmpeg-benchmark/filter_graph_test.c`
- Nginx: `nginx-benchmark/nginx_wrapper.c`
- Memcached: `memcached-benchmark/memcached_hashtable_standalone.c`
- Rsync: `rsync-benchmark/rsync_simple_option_test.c`

## Implementation Notes

1. **Field Access Analysis**: The PDG analyzes LLVM IR to determine read/write access patterns for struct fields

2. **eBPF Limitations**: 
   - Maximum 512 bytes stack size
   - Limited loop iterations
   - No dynamic memory allocation
   - Verification constraints

3. **Performance Considerations**:
   - Field masking (SP1) adds overhead on every function call
   - Invariant checks (SP3) scale with number of invariants
   - Protocol tracking (SP4) requires map lookups

4. **Future Enhancements**:
   - Real-time write prevention for SP2
   - Automatic protocol inference from traces
   - Performance optimizations
   - Support for more complex invariant types

## Example Workflow

1. Generate LLVM bitcode from source
2. Run Daikon to generate invariants
3. Create protocol specification
4. Run eBPFlex to generate eBPF programs
5. Load and attach eBPF programs
6. Monitor for policy violations

## Troubleshooting

- **Invariant parsing errors**: Check Daikon output format
- **Protocol violations**: Verify protocol specification matches actual usage
- **eBPF verification failures**: Simplify generated code or split into multiple programs
- **Performance issues**: Reduce number of monitored fields/invariants

## References

- Original eBPFlex paper: "Automatic Compartment Access Control Policy Enforcement with eBPF"
- Daikon invariant detector: https://plse.cs.washington.edu/daikon/
- BCC (BPF Compiler Collection): https://github.com/iovisor/bcc