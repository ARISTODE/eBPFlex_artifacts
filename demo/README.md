# eBPFlex Demo Pipeline

This demo demonstrates the complete eBPFlex pipeline for automatic generation of eBPF programs that enforce security policies (SP1-SP4) in compartmentalized applications.

## Demo Program Overview

The demo contains a simple compartmentalized application with:

### **Trusted Components** (`trusted.c`, `main.c`)
- `init_context()` - Initialize shared context with secure defaults
- `validate_context()` - Verify context integrity and detect violations
- `cleanup_context()` - Secure cleanup with data zeroing
- `update_secret_key()` - Trusted-only secret management
- `calculate_checksum()` - Integrity verification

### **Untrusted Components** (`untrusted.c`)
- `process_data()` - Data processing with limited field access
- `demonstrate_attacks()` - Shows attacks that policies should prevent

### **Shared Data Structure** (`demo.h`)
```c
typedef struct {
    uint32_t id;                    // Readable by untrusted, not writable
    uint32_t secret_key;            // Not accessible by untrusted  
    uint32_t config_flags;          // Readable and writable by untrusted
    uint32_t status;                // Readable by untrusted, not writable
    void *private_data;             // Not accessible by untrusted
    uint32_t buffer_size;           // Readable by untrusted, not writable
    char *buffer;                   // Readable and writable by untrusted
    uint32_t checksum;              // Not accessible by untrusted
} shared_context_t;
```

## Running the Demo

### **Complete Pipeline**
```bash
./run_demo_pipeline.sh
```

This runs the full pipeline:
1. **Build demo program** and boundary analyzer
2. **Identify compartments** (trusted vs untrusted functions)
3. **Extract interface functions** that cross boundaries
4. **Generate SP1/SP2 policies** for field access control
5. **Create SP3 invariants** (simulated Daikon analysis)
6. **Define SP4 protocol** specification
7. **Generate eBPF programs** with all security policies
8. **Display results** and generated files

### **Individual Steps**
```bash
# Build demo program
make all

# Run normal execution (shows attacks)
./demo

# Run boundary analysis
make analyze

# Generate eBPF programs (requires full PDG build)
make generate-ebpf
```

## Generated Files

### **Policy Files**
- `interface_funcs.txt` - Interface functions crossing trust boundaries
- `sp1_policies.txt` - Read access control (field masking)
- `sp2_policies.txt` - Write access control (field protection)
- `demo_invariants.txt` - Data validation invariants (SP3)
- `demo_protocol.txt` - Protocol specification (SP4)

### **eBPF Programs**
- `prog.ebpf.c` - eBPF kernel program with policy enforcement
- `prog.py` - Python userspace loader (using BCC)

## Security Policies Demonstrated

### **SP1: Read Access Control**
**Purpose**: Prevent data leakage from trusted to untrusted code
**Fields Masked**: `secret_key`, `private_data`, `checksum`
**Enforcement**: eBPF zeros/nullifies these fields before untrusted access

### **SP2: Write Access Control**
**Purpose**: Prevent data corruption by untrusted code
**Fields Protected**: `id`, `status`, `buffer_size`
**Enforcement**: eBPF detects unauthorized modifications and reports violations

### **SP3: Data Validation**
**Purpose**: Enforce data integrity through invariants
**Example Invariants**:
- `buffer_size == 1024`
- `status one of {1, 2}`
- `return one of {0, -1}`
**Enforcement**: eBPF validates invariants at function entry/exit

### **SP4: Protocol Enforcement**
**Purpose**: Ensure correct function call sequences
**Protocol**: `UNINITIALIZED → INITIALIZED → PROCESSING → VALIDATED → CLEANED`
**Enforcement**: eBPF tracks state machine and blocks invalid transitions

## Attack Demonstrations

The demo program includes attack demonstrations that show what the policies prevent:

1. **Secret Key Access** (SP1 violation)
2. **Read-only Field Modification** (SP2 violation)
3. **Private Data Access** (SP1 violation)
4. **Buffer Size Corruption** (SP2 violation)
5. **Status Field Corruption** (SP2 violation)

## Expected Output

### **Without eBPF Enforcement**
```
ATTACK 1: Attempting to read secret_key (SP1 should mask this)
Secret key value: 3405691582
ATTACK 2: Attempting to modify read-only id field (SP2 should detect this)
Changed ID from 12345 to 999
...
EXPECTED: Context validation failed due to attacks
```

### **With eBPF Enforcement** (when properly instrumented)
- SP1: Secret values would be masked (show as 0)
- SP2: Write violations would be blocked
- SP3: Invariant violations would prevent execution
- SP4: Invalid call sequences would be rejected

## System Requirements

### **Full Pipeline**
- LLVM/Clang (for bitcode generation)
- cmake (for PDG tool build)
- BCC/eBPF (for program loading)
- Root privileges (for eBPF loading)

### **Demo Only**
- GCC (fallback compilation)
- Basic POSIX shell

## Architecture

```
Demo Program → Boundary Analysis → Policy Generation → eBPF Generation
     ↓              ↓                    ↓               ↓
- LLVM IR      - Compartment ID    - SP1: Masking    - prog.ebpf.c
- Source       - Interface funcs   - SP2: Monitoring - prog.py  
- Execution    - Field access      - SP3: Validation
               - Call patterns     - SP4: FSM checks
```

This demo provides a complete working example of the eBPFlex system for automatic security policy enforcement in compartmentalized applications.