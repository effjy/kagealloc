#define _GNU_SOURCE
#include "kagealloc.h"
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define NUM_KEYS 4
#define PAGE_SIZE 4096
#define BLOCK_SIZE 64
#define BLOCKS_PER_PAGE (PAGE_SIZE / BLOCK_SIZE)

// Global assembly implementation of secure_wrpkru call gate (RICCG)
__asm__(
    ".globl secure_wrpkru\n"
    ".type secure_wrpkru, @function\n"
    ".align 16\n"
    "secure_wrpkru:\n"
    "    # Input: %edi = new PKRU value\n"
    "    # Input: %rsi = validation token\n"
    "    cmp %rsi, %r15\n"
    "    jne .abort_attack_asm\n"
    "    xor %ecx, %ecx\n"
    "    xor %edx, %edx\n"
    "    mov %edi, %eax\n"
    "    wrpkru\n"
    "    xor %eax, %eax\n"
    "    ret\n"
    ".abort_attack_asm:\n"
    "    # Print attack signature and abort\n"
    "    ud2\n"
);

// Metadata structure for Thread-Isolated Metadata Partitioning (TIMP)
typedef struct {
    int thread_id;
    int pkey;
    char padding[PAGE_SIZE - sizeof(int)*2]; // Pad to align to page boundary
} __attribute__((aligned(PAGE_SIZE))) thread_metadata_t;

// Structure for BKR pools
typedef struct {
    void* page_start;
    int pkey;
    int active_allocations;
    int is_quarantined;
    uint8_t free_map[BLOCKS_PER_PAGE];
} bkr_pool_t;

static bkr_pool_t pools[NUM_KEYS];
static int current_epoch = 0;
static uint64_t global_secret_token;
static int mpk_supported = 1;

// Metadata array for up to 2 threads
static thread_metadata_t* thread_metadata[2];

// Helper to modify PKRU state using our RICCG call gate
static void update_pkru_state(uint32_t new_val) {
    if (mpk_supported) {
        secure_wrpkru(new_val, global_secret_token);
    }
}

// Read current PKRU register
static inline uint32_t read_pkru(void) {
    uint32_t pkru = 0;
    if (mpk_supported) {
        __asm__ volatile("rdpkru" : "=a"(pkru) : "c"(0), "d"(0));
    }
    return pkru;
}

void kage_init(void) {
    // Generate secure random token
    FILE* urandom = fopen("/dev/urandom", "r");
    if (!urandom || fread(&global_secret_token, sizeof(global_secret_token), 1, urandom) != 1) {
        perror("Failed to generate secret token");
        exit(1);
    }
    if (urandom) fclose(urandom);

    // Load secret token into compiler-reserved register %r15
    // Reserve register %r15 via -ffixed-r15 ensures the compiler won't touch it
    __asm__ volatile("mov %0, %%r15" : : "r"(global_secret_token) : "r15");

    printf("[RICCG] Generated 64-bit secret token: 0x%lx\n", global_secret_token);
    printf("[RICCG] Validation token loaded into compiler-reserved register %%r15.\n");

    // Check if MPK is supported by the kernel
    int test_pkey = pkey_alloc(0, 0);
    if (test_pkey == -1) {
        printf("[MPK] pkey_alloc failed (errno: %d - %s). Running in Simulated Mode.\n", errno, strerror(errno));
        mpk_supported = 0;
    } else {
        printf("[MPK] Hardware protection keys supported! Running in Hardware-Enforced Mode.\n");
        pkey_free(test_pkey);
    }

    // Initialize BKR pools
    for (int i = 0; i < NUM_KEYS; i++) {
        pools[i].page_start = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (pools[i].page_start == MAP_FAILED) {
            perror("mmap failed");
            exit(1);
        }
        memset(pools[i].free_map, 1, BLOCKS_PER_PAGE); // Mark all blocks as free
        pools[i].active_allocations = 0;
        pools[i].is_quarantined = 0;

        if (mpk_supported) {
            // Allocate a hardware protection key for the pool (keys 1 to 4)
            pools[i].pkey = pkey_alloc(0, 0);
            if (pools[i].pkey == -1) {
                perror("pkey_alloc failed");
                exit(1);
            }
            if (pkey_mprotect(pools[i].page_start, PAGE_SIZE, PROT_READ | PROT_WRITE, pools[i].pkey) == -1) {
                perror("pkey_mprotect failed");
                exit(1);
            }
            printf("[BKR] Pool %d initialized at %p with PKEY %d\n", i, pools[i].page_start, pools[i].pkey);
        } else {
            pools[i].pkey = i + 1; // Fake key ID for simulation
            printf("[BKR] Pool %d initialized at %p (Simulated Key %d)\n", i, pools[i].page_start, pools[i].pkey);
        }
    }
}

void kage_thread_init(int thread_id) {
    if (thread_id < 0 || thread_id >= 2) return;

    // Allocate thread metadata page
    thread_metadata[thread_id] = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (thread_metadata[thread_id] == MAP_FAILED) {
        perror("mmap metadata failed");
        exit(1);
    }

    thread_metadata[thread_id]->thread_id = thread_id;

    if (mpk_supported) {
        thread_metadata[thread_id]->pkey = pkey_alloc(0, 0);
        if (thread_metadata[thread_id]->pkey == -1) {
            perror("pkey_alloc metadata failed");
            exit(1);
        }
        if (pkey_mprotect(thread_metadata[thread_id], PAGE_SIZE, PROT_READ | PROT_WRITE, thread_metadata[thread_id]->pkey) == -1) {
            perror("pkey_mprotect metadata failed");
            exit(1);
        }
        printf("[TIMP] Thread %d metadata page initialized at %p with PKEY %d\n", 
               thread_id, thread_metadata[thread_id], thread_metadata[thread_id]->pkey);
    } else {
        thread_metadata[thread_id]->pkey = 15; // Simulated metadata key
        printf("[TIMP] Thread %d metadata page initialized at %p (Simulated Key 15)\n", 
               thread_id, thread_metadata[thread_id]);
    }
}

void* kage_malloc(size_t size) {
    if (size > BLOCK_SIZE) {
        printf("[Allocator] Error: allocation size %zu exceeds block size %d\n", size, BLOCK_SIZE);
        return NULL;
    }

    bkr_pool_t* pool = &pools[current_epoch];

    // If pool is quarantined, we cannot allocate from it
    if (pool->is_quarantined) {
        printf("[BKR] Error: current pool %d is quarantined!\n", current_epoch);
        return NULL;
    }

    // Find free block
    int block_idx = -1;
    for (int i = 0; i < BLOCKS_PER_PAGE; i++) {
        if (pool->free_map[i] == 1) {
            block_idx = i;
            break;
        }
    }

    // If active epoch pool is full, rotate epoch
    if (block_idx == -1) {
        int old_epoch = current_epoch;
        current_epoch = (current_epoch + 1) % NUM_KEYS;
        printf("[BKR] Epoch transition: pool %d is full. Rotating to pool %d.\n", old_epoch, current_epoch);

        // Hardware quarantine: disable access to the old pool key
        bkr_pool_t* old_pool = &pools[old_epoch];
        old_pool->is_quarantined = 1;

        if (mpk_supported) {
            uint32_t current_pkru = read_pkru();
            // Disable Access (AD) for old_pool->pkey (bit 2 * pkey)
            uint32_t new_pkru = current_pkru | (1 << (2 * old_pool->pkey));
            printf("[BKR] Updating PKRU: Disabling key %d (New PKRU: 0x%x)\n", old_pool->pkey, new_pkru);
            update_pkru_state(new_pkru);
        } else {
            // Simulated quarantine: set page protection to PROT_NONE
            printf("[BKR] Simulated quarantine: mprotect(%p, PROT_NONE)\n", old_pool->page_start);
            mprotect(old_pool->page_start, PAGE_SIZE, PROT_NONE);
        }

        // Target new pool
        pool = &pools[current_epoch];
        if (pool->is_quarantined) {
            // Lazy recycling: if the target pool was quarantined, check if we can reclaim it
            if (pool->active_allocations == 0) {
                printf("[BKR] Lazy recycling: Pool %d active allocations is 0. Reclaiming pool.\n", current_epoch);
                pool->is_quarantined = 0;
                memset(pool->free_map, 1, BLOCKS_PER_PAGE);

                if (mpk_supported) {
                    uint32_t current_pkru = read_pkru();
                    // Enable access by clearing bit 2 * pkey
                    uint32_t new_pkru = current_pkru & ~(1 << (2 * pool->pkey));
                    update_pkru_state(new_pkru);
                } else {
                    mprotect(pool->page_start, PAGE_SIZE, PROT_READ | PROT_WRITE);
                }
            } else {
                printf("[BKR] Critical error: Pool %d is quarantined and still contains %d active allocations.\n", 
                       current_epoch, pool->active_allocations);
                return NULL;
            }
        }

        // Re-find block in new pool
        for (int i = 0; i < BLOCKS_PER_PAGE; i++) {
            if (pool->free_map[i] == 1) {
                block_idx = i;
                break;
            }
        }
    }

    pool->free_map[block_idx] = 0; // Mark allocated
    pool->active_allocations++;
    void* allocated_ptr = (void*)((uintptr_t)pool->page_start + (block_idx * BLOCK_SIZE));
    
    // Clear block contents to prevent information leaks
    memset(allocated_ptr, 0, BLOCK_SIZE);
    
    return allocated_ptr;
}

void kage_free(void* ptr) {
    if (!ptr) return;

    // Find which pool the pointer belongs to
    int pool_idx = -1;
    for (int i = 0; i < NUM_KEYS; i++) {
        uintptr_t start = (uintptr_t)pools[i].page_start;
        uintptr_t end = start + PAGE_SIZE;
        if ((uintptr_t)ptr >= start && (uintptr_t)ptr < end) {
            pool_idx = i;
            break;
        }
    }

    if (pool_idx == -1) {
        printf("[Allocator] Error: pointer %p does not belong to any pool.\n", ptr);
        return;
    }

    bkr_pool_t* pool = &pools[pool_idx];
    
    // Calculate block index
    int block_idx = ((uintptr_t)ptr - (uintptr_t)pool->page_start) / BLOCK_SIZE;

    if (pool->free_map[block_idx] == 1) {
        printf("[Allocator] Warning: double free detected at pointer %p!\n", ptr);
        return;
    }

    pool->free_map[block_idx] = 1; // Mark as free
    pool->active_allocations--;

    printf("[Allocator] Freed object in Pool %d at %p (Active allocations remaining: %d)\n", 
           pool_idx, ptr, pool->active_allocations);

    // If pool is quarantined and active allocations drop to 0, we can reclaim it
    if (pool->is_quarantined && pool->active_allocations == 0) {
        printf("[BKR] Pool %d quarantined allocations reached 0. Performing lazy recycle.\n", pool_idx);
        pool->is_quarantined = 0;
        memset(pool->free_map, 1, BLOCKS_PER_PAGE);

        if (mpk_supported) {
            uint32_t current_pkru = read_pkru();
            uint32_t new_pkru = current_pkru & ~(1 << (2 * pool->pkey));
            update_pkru_state(new_pkru);
        } else {
            mprotect(pool->page_start, PAGE_SIZE, PROT_READ | PROT_WRITE);
        }
    }
}

void simulate_rop_attack(uint32_t target_pkru_val) {
    printf("[Attack Simulation] Executing ROP attack simulation...\n");
    printf("[Attack Simulation] Attempting to jump directly to secure_wrpkru call gate instructions\n");
    printf("[Attack Simulation] Calling secure_wrpkru with a MALICIOUS (incorrect) validation token...\n");

    // The attacker tries to guess the token or leaves it unconfigured (e.g. 0xdeadbeef)
    secure_wrpkru(target_pkru_val, 0xdeadbeef);

    // The following code should NOT be reached
    printf("[Attack Simulation] Critical Failure: ROP attack succeeded! Call gate bypassed!\n");
}

void verify_cross_thread_metadata(int target_thread_id) {
    if (target_thread_id < 0 || target_thread_id >= 2) return;
    
    printf("[TIMP Test] Attempting to modify Thread %d metadata from current thread...\n", target_thread_id);
    
    if (!mpk_supported) {
        // Simulate that the other thread's metadata page is inaccessible to this thread
        printf("[TIMP Test] Simulated metadata isolation: mprotect(metadata_page, PROT_NONE)\n");
        mprotect(thread_metadata[target_thread_id], PAGE_SIZE, PROT_NONE);
    }
    
    // This write operation should trigger a segmentation fault / protection fault
    thread_metadata[target_thread_id]->thread_id = 999; 
    
    printf("[TIMP Test] Critical Failure: Successfully wrote to Thread %d metadata page!\n", target_thread_id);
}
