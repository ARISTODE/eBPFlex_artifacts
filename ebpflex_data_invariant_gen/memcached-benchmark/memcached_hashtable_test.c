#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

// Simple item structure mimicking memcached's item
typedef struct _stritem {
    struct _stritem *next;
    struct _stritem *prev;
    struct _stritem *h_next;
    time_t time;
    time_t exptime;
    int nbytes;
    unsigned short refcount;
    uint16_t it_flags;
    uint8_t slabs_clsid;
    uint8_t nkey;
    char data[];
} item;

// Mock memory allocation for items
item* create_item(const char *key, const char *value) {
    size_t nkey = strlen(key) + 1;
    size_t nvalue = strlen(value);
    size_t item_size = sizeof(item) + nkey + nvalue + 2;
    
    item *it = (item *)malloc(item_size);
    if (!it) return NULL;
    
    memset(it, 0, sizeof(item));
    it->nkey = nkey;
    it->nbytes = nvalue + 2;
    it->refcount = 1;
    it->time = time(NULL);
    it->exptime = 0;
    
    // Copy key and value into data area
    memcpy(it->data, key, nkey);
    memcpy(it->data + nkey, value, nvalue);
    
    return it;
}

// Simplified hash function
uint32_t simple_hash(const char *key, size_t nkey) {
    uint32_t hash = 5381;
    size_t i;
    
    for (i = 0; i < nkey; i++) {
        hash = ((hash << 5) + hash) + key[i];
    }
    
    return hash;
}

// Wrapper functions that will call the actual memcached functions
extern void assoc_init(const int hashpower_init);
extern item *assoc_find(const char *key, const size_t nkey, const uint32_t hv);
extern int assoc_insert(item *item, const uint32_t hv);
extern void assoc_delete(const char *key, const size_t nkey, const uint32_t hv);

// Test workload
void run_hashtable_workload() {
    printf("Starting memcached hashtable workload...\n");
    
    // Initialize hashtable with power of 16 (65536 buckets)
    assoc_init(16);
    
    // Test data
    const char *test_keys[] = {
        "key1", "key2", "key3", "key4", "key5",
        "test_key_6", "test_key_7", "test_key_8",
        "longer_test_key_9", "longer_test_key_10",
        "very_long_test_key_with_more_characters_11",
        "short", "medium_length", "extra_long_key_for_testing_12"
    };
    
    const char *test_values[] = {
        "value1", "value2", "value3", "value4", "value5",
        "test_value_6", "test_value_7", "test_value_8", 
        "longer_test_value_9", "longer_test_value_10",
        "very_long_test_value_with_more_characters_11",
        "tiny", "medium_sized_value", "extra_long_value_for_testing_12"
    };
    
    int num_items = sizeof(test_keys) / sizeof(test_keys[0]);
    
    // Insert items
    printf("\n--- INSERT PHASE ---\n");
    for (int i = 0; i < num_items; i++) {
        item *it = create_item(test_keys[i], test_values[i]);
        if (it) {
            uint32_t hv = simple_hash(test_keys[i], strlen(test_keys[i]));
            int result = assoc_insert(it, hv);
            printf("Insert key='%s' hash=%u result=%d\n", test_keys[i], hv, result);
        }
    }
    
    // Lookup items
    printf("\n--- LOOKUP PHASE ---\n");
    for (int i = 0; i < num_items; i++) {
        uint32_t hv = simple_hash(test_keys[i], strlen(test_keys[i]));
        item *found = assoc_find(test_keys[i], strlen(test_keys[i]), hv);
        printf("Find key='%s' hash=%u found=%s\n", 
               test_keys[i], hv, found ? "yes" : "no");
    }
    
    // Lookup non-existent items
    printf("\n--- LOOKUP NON-EXISTENT ---\n");
    const char *missing_keys[] = {"missing1", "missing2", "not_there"};
    for (int i = 0; i < 3; i++) {
        uint32_t hv = simple_hash(missing_keys[i], strlen(missing_keys[i]));
        item *found = assoc_find(missing_keys[i], strlen(missing_keys[i]), hv);
        printf("Find key='%s' hash=%u found=%s\n", 
               missing_keys[i], hv, found ? "yes" : "no");
    }
    
    // Delete some items
    printf("\n--- DELETE PHASE ---\n");
    for (int i = 0; i < num_items; i += 2) {
        uint32_t hv = simple_hash(test_keys[i], strlen(test_keys[i]));
        assoc_delete(test_keys[i], strlen(test_keys[i]), hv);
        printf("Delete key='%s' hash=%u\n", test_keys[i], hv);
    }
    
    // Verify deletions
    printf("\n--- VERIFY DELETIONS ---\n");
    for (int i = 0; i < num_items; i++) {
        uint32_t hv = simple_hash(test_keys[i], strlen(test_keys[i]));
        item *found = assoc_find(test_keys[i], strlen(test_keys[i]), hv);
        printf("Find key='%s' after delete: found=%s\n", 
               test_keys[i], found ? "yes" : "no");
    }
    
    // Test with collision-prone keys (if possible)
    printf("\n--- COLLISION TEST ---\n");
    for (int i = 0; i < 5; i++) {
        char key[32];
        sprintf(key, "collision_key_%d", i * 1000);
        item *it = create_item(key, "collision_value");
        if (it) {
            uint32_t hv = simple_hash(key, strlen(key));
            assoc_insert(it, hv);
            printf("Insert collision test key='%s' hash=%u\n", key, hv);
        }
    }
}

int main() {
    run_hashtable_workload();
    return 0;
}