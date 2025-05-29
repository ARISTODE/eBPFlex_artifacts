#include "demo.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Static data for demonstration
static shared_context_t* global_contexts[10] = {0};
static uint32_t context_count = 0;

// Trusted function: Initialize a new context
shared_context_t* init_context(uint32_t id) {
    if (context_count >= 10) {
        return NULL;
    }
    
    shared_context_t *ctx = malloc(sizeof(shared_context_t));
    if (!ctx) {
        return NULL;
    }
    
    // Initialize with trusted values
    ctx->id = id;
    ctx->secret_key = 0xDEADBEEF;  // Secret value not accessible to untrusted
    ctx->config_flags = 0;          // Writable by untrusted
    ctx->status = 1;                // Active status
    ctx->private_data = malloc(256); // Private data not accessible to untrusted
    ctx->buffer_size = 1024;        // Fixed buffer size
    ctx->buffer = malloc(1024);     // Buffer accessible to untrusted
    ctx->checksum = 0;              // Will be calculated later
    
    if (!ctx->private_data || !ctx->buffer) {
        free(ctx->private_data);
        free(ctx->buffer);
        free(ctx);
        return NULL;
    }
    
    memset(ctx->buffer, 0, 1024);
    memset(ctx->private_data, 0, 256);
    
    global_contexts[context_count++] = ctx;
    return ctx;
}

// Trusted function: Validate context integrity
int validate_context(shared_context_t *ctx) {
    if (!ctx) {
        return -1;
    }
    
    // Check that untrusted code hasn't corrupted read-only fields
    if (ctx->id == 0) {
        printf("ERROR: Context ID corrupted!\n");
        return -1;
    }
    
    if (ctx->status != 1 && ctx->status != 2) {
        printf("ERROR: Invalid status value: %u\n", ctx->status);
        return -1;
    }
    
    if (ctx->buffer_size != 1024) {
        printf("ERROR: Buffer size corrupted: %u\n", ctx->buffer_size);
        return -1;
    }
    
    if (!ctx->buffer || !ctx->private_data) {
        printf("ERROR: Null pointers detected!\n");
        return -1;
    }
    
    // Verify checksum matches expected value
    uint32_t expected_checksum = calculate_checksum(ctx);
    if (ctx->checksum != 0 && ctx->checksum != expected_checksum) {
        printf("ERROR: Checksum mismatch! Expected: %u, Got: %u\n", 
               expected_checksum, ctx->checksum);
        return -1;
    }
    
    return 0;
}

// Trusted function: Calculate integrity checksum
uint32_t calculate_checksum(shared_context_t *ctx) {
    if (!ctx || !ctx->buffer) {
        return 0;
    }
    
    uint32_t checksum = ctx->id ^ ctx->config_flags ^ ctx->status ^ ctx->buffer_size;
    
    // Simple checksum of buffer contents
    for (int i = 0; i < 64 && i < ctx->buffer_size; i++) {
        checksum ^= (uint32_t)ctx->buffer[i];
    }
    
    return checksum;
}

// Trusted function: Update secret key (should never be called by untrusted)
void update_secret_key(shared_context_t *ctx, uint32_t new_key) {
    if (!ctx) {
        return;
    }
    
    printf("Updating secret key from %u to %u\n", ctx->secret_key, new_key);
    ctx->secret_key = new_key;
    
    // Update checksum after secret change
    ctx->checksum = calculate_checksum(ctx);
}

// Trusted function: Get private data (should never be called by untrusted)
void* get_private_data(shared_context_t *ctx) {
    if (!ctx) {
        return NULL;
    }
    
    return ctx->private_data;
}

// Trusted function: Cleanup context
void cleanup_context(shared_context_t *ctx) {
    if (!ctx) {
        return;
    }
    
    // Find and remove from global array
    for (int i = 0; i < context_count; i++) {
        if (global_contexts[i] == ctx) {
            global_contexts[i] = global_contexts[context_count - 1];
            global_contexts[context_count - 1] = NULL;
            context_count--;
            break;
        }
    }
    
    // Clear sensitive data before freeing
    memset(ctx->private_data, 0, 256);
    ctx->secret_key = 0;
    
    free(ctx->private_data);
    free(ctx->buffer);
    free(ctx);
}