#ifndef KAGEALLOC_H
#define KAGEALLOC_H

#include <stddef.h>
#include <stdint.h>

// Initializes KageAlloc (generates cryptographic token, loads %r15)
void kage_init(void);

// Allocates memory of 'size' bytes using BKR (Epoch allocation)
void* kage_malloc(size_t size);

// Deallocates the memory space pointed to by 'ptr' (enforces quarantine)
void kage_free(void* ptr);

// Registers a thread and sets up its private metadata page and key (TIMP)
void kage_thread_init(int thread_id);

// Simulates a ROP attack trying to jump into the middle of wrpkru assembly
void simulate_rop_attack(uint32_t target_pkru_val);

// Verifies access to thread-local metadata of another thread (to demonstrate TIMP)
void verify_cross_thread_metadata(int target_thread_id);

// Internal secure wrpkru call gate
extern void secure_wrpkru(uint32_t new_pkru_val, uint64_t validation_token);

#endif // KAGEALLOC_H
