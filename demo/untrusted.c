#include "demo.h"
#include <string.h>
#include <stdio.h>

// Untrusted function: Process data using the context
// This function can only access certain fields of shared_context_t
int process_data(shared_context_t *ctx, const char *input, uint32_t len) {
    if (!ctx || !input) {
        return -1;
    }
    
    // Untrusted code should only read allowed fields
    printf("Processing data for context ID: %u\n", ctx->id);
    printf("Current config flags: %u\n", ctx->config_flags);
    printf("Buffer size: %u\n", ctx->buffer_size);
    
    // Check input length against buffer size
    if (len > ctx->buffer_size) {
        printf("Input too large: %u > %u\n", len, ctx->buffer_size);
        return -1;
    }
    
    // Copy input to buffer (untrusted can write to buffer)
    memcpy(ctx->buffer, input, len);
    
    // Untrusted code might try to modify config_flags (this should be allowed)
    ctx->config_flags |= 0x1;  // Set processing flag
    
    // The following are policy violations that should be caught:
    
    // ATTACK 1: Try to read secret_key (SP1 violation - should be masked)
    // printf("Secret key: %u\n", ctx->secret_key);
    
    // ATTACK 2: Try to modify read-only id field (SP2 violation)
    // ctx->id = 999;
    
    // ATTACK 3: Try to modify read-only status field (SP2 violation)  
    // ctx->status = 99;
    
    // ATTACK 4: Try to read private_data pointer (SP1 violation - should be masked)
    // printf("Private data pointer: %p\n", ctx->private_data);
    
    // ATTACK 5: Try to modify buffer_size (SP2 violation)
    // ctx->buffer_size = 2048;
    
    return 0;
}

// Demonstration of policy violations for testing
void demonstrate_attacks(shared_context_t *ctx) {
    if (!ctx) return;
    
    printf("\n=== Demonstrating Policy Violations ===\n");
    
    printf("ATTACK 1: Attempting to read secret_key (SP1 should mask this)\n");
    printf("Secret key value: %u\n", ctx->secret_key);
    
    printf("ATTACK 2: Attempting to modify read-only id field (SP2 should detect this)\n");
    uint32_t original_id = ctx->id;
    ctx->id = 999;
    printf("Changed ID from %u to %u\n", original_id, ctx->id);
    
    printf("ATTACK 3: Attempting to read private_data pointer (SP1 should mask this)\n");
    printf("Private data pointer: %p\n", ctx->private_data);
    
    printf("ATTACK 4: Attempting to modify buffer_size (SP2 should detect this)\n");
    uint32_t original_size = ctx->buffer_size;
    ctx->buffer_size = 2048;
    printf("Changed buffer size from %u to %u\n", original_size, ctx->buffer_size);
    
    printf("ATTACK 5: Attempting to modify status (SP2 should detect this)\n");
    uint32_t original_status = ctx->status;
    ctx->status = 99;
    printf("Changed status from %u to %u\n", original_status, ctx->status);
}