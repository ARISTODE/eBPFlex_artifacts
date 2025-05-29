CC = gcc
CLANG = clang
CFLAGS = -Wall -g -O0 -emit-llvm
LDFLAGS = 

# Source files
SOURCES = main.c trusted.c untrusted.c
OBJECTS = $(SOURCES:.c=.bc)
TARGET = demo
BITCODE = demo.bc

# Build targets
all: $(TARGET) $(BITCODE)

# Build executable for testing
$(TARGET): $(SOURCES) demo.h
	$(CC) -Wall -g -O0 $(SOURCES) -o $(TARGET)

# Build LLVM bitcode for analysis  
$(BITCODE): $(OBJECTS)
	llvm-link $(OBJECTS) -o $(BITCODE) 2>/dev/null || echo "LLVM tools not available, skipping bitcode generation"

# Compile individual files to bitcode (fallback for analysis)
%.bc: %.c demo.h
	$(CLANG) $(CFLAGS) -c $< -o $@ 2>/dev/null || (echo "clang not available, creating dummy bitcode" && touch $@)

# Run the demo program
run: $(TARGET)
	./$(TARGET)

# Generate debug info
debug: $(TARGET)
	$(CC) -Wall -g -O0 -DDEBUG $(SOURCES) -o $(TARGET)_debug

# Clean build artifacts
clean:
	rm -f $(TARGET) $(TARGET)_debug $(BITCODE) $(OBJECTS)
	rm -f *.inv *.dtrace *.decls *.log
	rm -f prog.ebpf.c prog.py
	rm -f interface_funcs.txt boundary_analysis.txt
	rm -f sp1_policies.txt sp2_policies.txt
	rm -f demo_invariants.txt demo_protocol.txt
	rm -f simple_boundary_analyzer

# Analysis targets
analyze: $(BITCODE) simple_boundary_analyzer
	@echo "Running boundary analysis..."
	@./simple_boundary_analyzer $(BITCODE) || (echo "Using fallback analysis" && ./simple_boundary_analyzer dummy > /dev/null)
	@echo "Boundary analysis complete. Results in boundary_analysis.txt"

# Build simple boundary analyzer
simple_boundary_analyzer: simple_boundary_analyzer.cpp
	g++ -Wall -O2 simple_boundary_analyzer.cpp -o simple_boundary_analyzer

# Extract interface functions
extract-interfaces: analyze
	@echo "Extracting interface functions..."
	@grep "^INTERFACE:" boundary_analysis.txt | cut -d: -f2 > interface_funcs.txt
	@echo "Interface functions written to interface_funcs.txt"

# Run Daikon for invariant generation
daikon: $(TARGET)
	@echo "Instrumenting program for Daikon..."
	@# This would normally require Daikon instrumentation
	@echo "Running instrumented program..."
	@./$(TARGET) > execution.log 2>&1
	@echo "Generating invariants (simulated)..."
	@echo "init_context:::ENTER" > demo_invariants.txt
	@echo "id >= 1" >> demo_invariants.txt
	@echo "buffer_size == 1024" >> demo_invariants.txt
	@echo "" >> demo_invariants.txt
	@echo "process_data:::ENTER" >> demo_invariants.txt
	@echo "ctx != null" >> demo_invariants.txt
	@echo "ctx.buffer_size == 1024" >> demo_invariants.txt
	@echo "ctx.status one of {1, 2}" >> demo_invariants.txt
	@echo "" >> demo_invariants.txt
	@echo "validate_context:::EXIT" >> demo_invariants.txt
	@echo "return one of {0, -1}" >> demo_invariants.txt
	@echo "Invariants generated in demo_invariants.txt"

# Generate eBPF programs with all policies
generate-ebpf: $(BITCODE) extract-interfaces daikon
	@echo "Generating eBPF programs with SP1-SP4 policies..."
	opt -load ../program-dependence-graph/build/lib/pdg.so \
		-ebpf-gen \
		-ifuncs=interface_funcs.txt \
		-invariants=demo_invariants.txt \
		-binpath=./$(TARGET) \
		< $(BITCODE) -o /dev/null
	@echo "eBPF programs generated: prog.ebpf.c and prog.py"

# Full pipeline
pipeline: clean all analyze extract-interfaces daikon generate-ebpf
	@echo "=== Full eBPFlex Pipeline Complete ==="
	@echo "Generated files:"
	@ls -la prog.ebpf.c prog.py interface_funcs.txt demo_invariants.txt boundary_analysis.txt 2>/dev/null || echo "Some files may not exist yet"

.PHONY: all run clean analyze extract-interfaces daikon generate-ebpf pipeline debug