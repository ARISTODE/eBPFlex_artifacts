#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Simple test functions that mimic nginx behavior patterns
typedef struct {
    void *start;
    void *end;
    void *current;
    size_t size;
} ngx_pool_t;

typedef struct {
    unsigned char *data;
    size_t len;
} ngx_str_t;

// Mimics nginx's memory allocation
void* test_ngx_palloc(ngx_pool_t *pool, size_t size) {
    if (!pool || size == 0) return NULL;
    if (size > pool->size) return NULL;
    
    void *p = pool->current;
    pool->current = (char*)pool->current + size;
    return p;
}

// Mimics nginx's string operations
int test_ngx_strcmp(const char *s1, const char *s2) {
    if (!s1 || !s2) return -1;
    return strcmp(s1, s2);
}

// Mimics nginx array operations
int test_ngx_array_init(void *array, int n, size_t size) {
    if (!array || n <= 0 || size == 0) return -1;
    if (n > 1000) return -1; // upper bound
    return 0;
}

// Test HTTP status code handling
int test_http_status_check(int status) {
    if (status >= 100 && status < 200) return 1; // informational
    if (status >= 200 && status < 300) return 2; // success
    if (status >= 300 && status < 400) return 3; // redirection
    if (status >= 400 && status < 500) return 4; // client error
    if (status >= 500 && status < 600) return 5; // server error
    return 0; // invalid
}

int main() {
    // Test memory allocation patterns
    ngx_pool_t pool;
    char buffer[1024];
    pool.start = buffer;
    pool.end = buffer + 1024;
    pool.current = buffer;
    pool.size = 1024;
    
    for (int i = 0; i < 10; i++) {
        void *p = test_ngx_palloc(&pool, i * 10);
        printf("Alloc %d: %p\n", i * 10, p);
    }
    
    // Test string comparisons
    const char *strings[] = {"GET", "POST", "HEAD", "PUT", "DELETE"};
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 5; j++) {
            int result = test_ngx_strcmp(strings[i], strings[j]);
            printf("Compare %s vs %s: %d\n", strings[i], strings[j], result);
        }
    }
    
    // Test array initialization
    char array[100];
    for (int n = 1; n <= 20; n++) {
        int result = test_ngx_array_init(array, n, sizeof(int));
        printf("Array init n=%d: %d\n", n, result);
    }
    
    // Test HTTP status codes
    int status_codes[] = {100, 200, 301, 404, 500, 600, 0, -1};
    for (int i = 0; i < 8; i++) {
        int result = test_http_status_check(status_codes[i]);
        printf("Status %d: %d\n", status_codes[i], result);
    }
    
    return 0;
}