#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Very simple hash table for testing Daikon

typedef struct node {
    char *key;
    int value;
    struct node *next;
} node_t;

#define TABLE_SIZE 10
node_t *table[TABLE_SIZE];

unsigned int hash(const char *key) {
    unsigned int h = 0;
    while (*key) {
        h = h * 31 + *key++;
    }
    return h % TABLE_SIZE;
}

void insert(const char *key, int value) {
    unsigned int index = hash(key);
    node_t *n = malloc(sizeof(node_t));
    n->key = strdup(key);
    n->value = value;
    n->next = table[index];
    table[index] = n;
}

int find(const char *key) {
    unsigned int index = hash(key);
    node_t *n = table[index];
    while (n) {
        if (strcmp(n->key, key) == 0) {
            return n->value;
        }
        n = n->next;
    }
    return -1;
}

void delete(const char *key) {
    unsigned int index = hash(key);
    node_t **pp = &table[index];
    while (*pp) {
        node_t *n = *pp;
        if (strcmp(n->key, key) == 0) {
            *pp = n->next;
            free(n->key);
            free(n);
            return;
        }
        pp = &n->next;
    }
}

int main() {
    // Initialize table
    for (int i = 0; i < TABLE_SIZE; i++) {
        table[i] = NULL;
    }
    
    // Test operations
    insert("one", 1);
    insert("two", 2);
    insert("three", 3);
    
    printf("find(one) = %d\n", find("one"));
    printf("find(two) = %d\n", find("two"));
    printf("find(three) = %d\n", find("three"));
    printf("find(four) = %d\n", find("four"));
    
    delete("two");
    printf("After delete: find(two) = %d\n", find("two"));
    
    return 0;
}