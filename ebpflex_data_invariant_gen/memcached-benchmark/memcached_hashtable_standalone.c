#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <pthread.h>

// Simplified version of memcached's hashtable for Daikon analysis

typedef struct _stritem {
    struct _stritem *h_next;    // hash chain next
    uint8_t nkey;              // key length
    char data[];               // key stored here
} item;

#define ITEM_key(item) ((item)->data)

// Hash table parameters
static unsigned int hashpower = 16;  // 2^16 = 65536 buckets
static item** primary_hashtable = NULL;

#define hashsize(n) ((uint64_t)1<<(n))
#define hashmask(n) (hashsize(n)-1)

// Simple hash function
static uint32_t hash_func(const char *key, size_t nkey) {
    uint32_t hash = 5381;
    for (size_t i = 0; i < nkey; i++) {
        hash = ((hash << 5) + hash) + key[i];
    }
    return hash;
}

// Initialize hash table
void assoc_init(const int hashtable_init) {
    if (hashtable_init) {
        hashpower = hashtable_init;
    }
    primary_hashtable = calloc(hashsize(hashpower), sizeof(void *));
    if (!primary_hashtable) {
        fprintf(stderr, "Failed to init hashtable.\n");
        exit(EXIT_FAILURE);
    }
    printf("Initialized hashtable with %lu buckets\n", hashsize(hashpower));
}

// Find an item in the hash table
item *assoc_find(const char *key, const size_t nkey, const uint32_t hv) {
    item *it;
    uint32_t bucket = hv & hashmask(hashpower);
    
    it = primary_hashtable[bucket];
    
    int depth = 0;
    while (it) {
        if ((nkey == it->nkey) && (memcmp(key, ITEM_key(it), nkey) == 0)) {
            printf("Found key '%.*s' at depth %d in bucket %u\n", 
                   (int)nkey, key, depth, bucket);
            return it;
        }
        it = it->h_next;
        depth++;
    }
    
    printf("Key '%.*s' not found in bucket %u\n", (int)nkey, key, bucket);
    return NULL;
}

// Insert an item into the hash table
int assoc_insert(item *it, const uint32_t hv) {
    uint32_t bucket = hv & hashmask(hashpower);
    
    // Insert at head of chain
    it->h_next = primary_hashtable[bucket];
    primary_hashtable[bucket] = it;
    
    printf("Inserted key '%.*s' into bucket %u\n", 
           (int)it->nkey, ITEM_key(it), bucket);
    return 1;
}

// Delete an item from the hash table
void assoc_delete(const char *key, const size_t nkey, const uint32_t hv) {
    uint32_t bucket = hv & hashmask(hashpower);
    item **before = &primary_hashtable[bucket];
    
    while (*before) {
        item *it = *before;
        if ((nkey == it->nkey) && (memcmp(key, ITEM_key(it), nkey) == 0)) {
            *before = it->h_next;
            printf("Deleted key '%.*s' from bucket %u\n", 
                   (int)nkey, key, bucket);
            free(it);
            return;
        }
        before = &it->h_next;
    }
    
    printf("Key '%.*s' not found for deletion in bucket %u\n", 
           (int)nkey, key, bucket);
}

// Helper to create an item
item* create_item(const char *key) {
    size_t nkey = strlen(key);
    item *it = malloc(sizeof(item) + nkey + 1);
    if (!it) return NULL;
    
    it->h_next = NULL;
    it->nkey = nkey;
    memcpy(it->data, key, nkey);
    it->data[nkey] = '\0';
    
    return it;
}

// Main test function
int main() {
    printf("Memcached Hashtable Standalone Test\n");
    printf("===================================\n\n");
    
    // Initialize with smaller table for easier tracing
    assoc_init(4);  // 2^4 = 16 buckets
    
    // Test data - designed to exercise different scenarios
    const char *keys[] = {
        "a", "b", "c", "d", "e",              // short keys
        "key1", "key2", "key3",               // medium keys
        "longerkey1", "longerkey2",           // longer keys
        "verylongkey123", "verylongkey456",   // very long keys
        "collision1", "collision2"            // might collide
    };
    
    int num_keys = sizeof(keys) / sizeof(keys[0]);
    
    // INSERT phase
    printf("=== INSERT PHASE ===\n");
    for (int i = 0; i < num_keys; i++) {
        item *it = create_item(keys[i]);
        if (it) {
            uint32_t hv = hash_func(keys[i], strlen(keys[i]));
            assoc_insert(it, hv);
        }
    }
    
    // FIND phase - all keys
    printf("\n=== FIND PHASE (existing keys) ===\n");
    for (int i = 0; i < num_keys; i++) {
        uint32_t hv = hash_func(keys[i], strlen(keys[i]));
        item *found = assoc_find(keys[i], strlen(keys[i]), hv);
        assert(found != NULL);
    }
    
    // FIND phase - non-existent keys
    printf("\n=== FIND PHASE (non-existent keys) ===\n");
    const char *missing[] = {"notfound1", "notfound2", "xyz"};
    for (int i = 0; i < 3; i++) {
        uint32_t hv = hash_func(missing[i], strlen(missing[i]));
        item *found = assoc_find(missing[i], strlen(missing[i]), hv);
        assert(found == NULL);
    }
    
    // DELETE phase - every other key
    printf("\n=== DELETE PHASE ===\n");
    for (int i = 0; i < num_keys; i += 2) {
        uint32_t hv = hash_func(keys[i], strlen(keys[i]));
        assoc_delete(keys[i], strlen(keys[i]), hv);
    }
    
    // VERIFY phase
    printf("\n=== VERIFY PHASE ===\n");
    for (int i = 0; i < num_keys; i++) {
        uint32_t hv = hash_func(keys[i], strlen(keys[i]));
        item *found = assoc_find(keys[i], strlen(keys[i]), hv);
        if (i % 2 == 0) {
            assert(found == NULL);  // Should be deleted
        } else {
            assert(found != NULL);  // Should still exist
        }
    }
    
    printf("\nAll tests completed successfully!\n");
    return 0;
}