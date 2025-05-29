#!/usr/bin/env python3
from bcc import BPF

# Load eBPF program
b = BPF(src_file="prog.ebpf.c")

# Attach to demo program
b.attach_uprobe(name="./demo", sym="init_context", fn_name="uprobe_init_context")
b.attach_uprobe(name="./demo", sym="process_data", fn_name="uprobe_process_data")

print("eBPF program loaded. Run './demo' to see enforcement in action.")
print("Press Ctrl+C to stop monitoring...")

try:
    b.trace_print()
except KeyboardInterrupt:
    pass
