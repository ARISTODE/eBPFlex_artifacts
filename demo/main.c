#include "demo.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// External function from untrusted module
extern void demonstrate_attacks(shared_context_t *ctx);

int main() {
    printf("=== eBPFlex Demo Program ===\n");
    printf("This program demonstrates trusted/untrusted compartments\n\n");
    
    // Step 1: Initialize context (trusted operation)
    printf("1. Initializing context (trusted)...\n");
    shared_context_t *ctx = init_context(12345);
    if (!ctx) {
        printf("Failed to initialize context\n");
        return 1;
    }
    printf("Context initialized with ID: %u\n", ctx->id);
    
    // Step 2: Validate initial state (trusted operation)
    printf("\n2. Validating initial context (trusted)...\n");
    if (validate_context(ctx) != 0) {
        printf("Initial context validation failed\n");
        cleanup_context(ctx);
        return 1;
    }
    printf("Initial context validation passed\n");
    
    // Step 3: Process data (crosses to untrusted)
    printf("\n3. Processing data (untrusted)...\n");
    const char *test_data = "Hello, this is test data for processing";
    int result = process_data(ctx, test_data, strlen(test_data));
    printf("Process data result: %d\n", result);
    
    // Step 4: Validate after untrusted access (trusted operation)
    printf("\n4. Validating context after untrusted access (trusted)...\n");
    if (validate_context(ctx) != 0) {
        printf("Context validation failed after untrusted access\n");
    } else {
        printf("Context validation passed after untrusted access\n");
    }
    
    // Step 5: Update secret (trusted operation)
    printf("\n5. Updating secret key (trusted only)...\n");
    update_secret_key(ctx, 0xCAFEBABE);
    
    // Step 6: Demonstrate attacks (this will show what policies should prevent)
    printf("\n6. Demonstrating attacks (this shows what should be prevented)...\n");
    demonstrate_attacks(ctx);
    
    // Step 7: Final validation (trusted operation)
    printf("\n7. Final validation (trusted)...\n");
    if (validate_context(ctx) != 0) {
        printf("EXPECTED: Context validation failed due to attacks\n");
    } else {
        printf("Context validation passed\n");
    }
    
    // Step 8: Cleanup (trusted operation)
    printf("\n8. Cleaning up context (trusted)...\n");
    cleanup_context(ctx);
    
    printf("\n=== Demo Complete ===\n");
    printf("This program should be instrumented with eBPF to enforce:\n");
    printf("- SP1: Mask secret_key and private_data from untrusted access\n");
    printf("- SP2: Prevent modification of id, status, buffer_size\n");
    printf("- SP3: Enforce data invariants (e.g., buffer_size == 1024)\n");
    printf("- SP4: Enforce call protocol (init -> process -> validate -> cleanup)\n");
    
    return 0;
}