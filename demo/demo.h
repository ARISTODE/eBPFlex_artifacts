#ifndef DEMO_H
#define DEMO_H

#include <stdint.h>
#include <stdbool.h>

// Shared data structure that crosses trust boundaries
typedef struct {
    uint32_t id;                    // Readable by untrusted, not writable
    uint32_t secret_key;            // Not readable by untrusted, not writable  
    uint32_t config_flags;          // Readable and writable by untrusted
    uint32_t status;                // Readable by untrusted, not writable
    void *private_data;             // Not readable by untrusted, not writable
    uint32_t buffer_size;           // Readable by untrusted, not writable
    char *buffer;                   // Readable and writable by untrusted
    uint32_t checksum;              // Not readable by untrusted, not writable
} shared_context_t;

// Interface functions - these cross the trust boundary
extern shared_context_t* init_context(uint32_t id);
extern int process_data(shared_context_t *ctx, const char *input, uint32_t len);
extern int validate_context(shared_context_t *ctx);
extern void cleanup_context(shared_context_t *ctx);

// Trusted-only functions (should not be called by untrusted code)
extern void update_secret_key(shared_context_t *ctx, uint32_t new_key);
extern void* get_private_data(shared_context_t *ctx);
extern uint32_t calculate_checksum(shared_context_t *ctx);

#endif // DEMO_H