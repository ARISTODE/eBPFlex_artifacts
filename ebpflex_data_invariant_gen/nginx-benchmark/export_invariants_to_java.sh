#!/bin/bash

# Script to export Daikon invariants to Java assertions
# Usage: ./export_invariants_to_java.sh <invariant_file.inv.gz> <output_directory>

if [ $# -lt 2 ]; then
    echo "Usage: $0 <invariant_file.inv.gz> <output_directory>"
    echo "Example: $0 nginx_v3.inv.gz ./assertions"
    exit 1
fi

INVARIANT_FILE=$1
OUTPUT_DIR=$2
DAIKON_JAR="daikon/daikon.jar"

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Extract base name from invariant file
BASE_NAME=$(basename "$INVARIANT_FILE" .inv.gz)

echo "=== Exporting Daikon Invariants to Java Assertions ==="
echo "Input: $INVARIANT_FILE"
echo "Output directory: $OUTPUT_DIR"
echo ""

# Step 1: Convert invariants to Java format
echo "Step 1: Converting invariants to Java format..."
JAVA_INVARIANTS="$OUTPUT_DIR/${BASE_NAME}_invariants.java"
java -cp "$DAIKON_JAR" daikon.PrintInvariants --format Java "$INVARIANT_FILE" > "$JAVA_INVARIANTS"

if [ $? -eq 0 ]; then
    echo "✓ Created: $JAVA_INVARIANTS"
else
    echo "✗ Failed to convert invariants"
    exit 1
fi

# Step 2: Generate assertion classes
echo ""
echo "Step 2: Generating assertion classes..."

# Compile the converter if needed
if [ ! -f "InvariantToAssertionConverter.class" ]; then
    echo "Compiling converter..."
    javac InvariantToAssertionConverter.java
fi

# Generate assertions
ASSERTIONS_FILE="$OUTPUT_DIR/${BASE_NAME}Assertions.java"
java InvariantToAssertionConverter "$JAVA_INVARIANTS" "$ASSERTIONS_FILE"

if [ $? -eq 0 ]; then
    echo "✓ Created: $ASSERTIONS_FILE"
else
    echo "✗ Failed to generate assertions"
    exit 1
fi

# Step 3: Also export in other formats for reference
echo ""
echo "Step 3: Exporting additional formats..."

# ESC/Java format
ESC_FILE="$OUTPUT_DIR/${BASE_NAME}_esc.txt"
java -cp "$DAIKON_JAR" daikon.PrintInvariants --format ESC/Java "$INVARIANT_FILE" > "$ESC_FILE" 2>/dev/null
echo "✓ Created: $ESC_FILE (ESC/Java format)"

# JML format
JML_FILE="$OUTPUT_DIR/${BASE_NAME}_jml.txt"
java -cp "$DAIKON_JAR" daikon.PrintInvariants --format JML "$INVARIANT_FILE" > "$JML_FILE" 2>/dev/null
echo "✓ Created: $JML_FILE (JML format)"

# Step 4: Create a summary report
echo ""
echo "Step 4: Creating summary report..."
SUMMARY_FILE="$OUTPUT_DIR/${BASE_NAME}_summary.txt"

cat > "$SUMMARY_FILE" << EOF
Daikon Invariant Export Summary
==============================
Generated: $(date)
Source: $INVARIANT_FILE

Files created:
- ${BASE_NAME}_invariants.java: Raw Java-formatted invariants
- ${BASE_NAME}Assertions.java: Generated assertion classes
- ${BASE_NAME}_esc.txt: ESC/Java format (for static checking)
- ${BASE_NAME}_jml.txt: JML format (Java Modeling Language)

Usage:
1. Include the generated assertion class in your project
2. Call assertion methods at appropriate points:
   - assertPreconditions() at method entry
   - assertPostconditions() at method exit
3. Run with assertions enabled: java -ea YourClass

Example:
    public int myMethod(int param) {
        MyMethodAssertions.assertPreconditions(param);
        int oldParam = param;
        
        // Your method logic here
        int result = ...;
        
        MyMethodAssertions.assertPostconditions(param, result, oldParam);
        return result;
    }
EOF

echo "✓ Created: $SUMMARY_FILE"

echo ""
echo "=== Export Complete ==="
echo "All files have been generated in: $OUTPUT_DIR"
echo "See $SUMMARY_FILE for usage instructions."