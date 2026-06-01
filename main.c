#include "kagealloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <signal.h>
#include <string.h>

#define PAGE_SIZE 4096
#define BLOCK_SIZE 64
#define BLOCKS_PER_PAGE (PAGE_SIZE / BLOCK_SIZE)

// Helper to run a test inside a fork and check the terminating signal
void run_isolated_test(const char* test_name, void (*test_func)(void), int expected_signal) {
    printf("\n=== Running Test: %s ===\n", test_name);
    pid_t pid = fork();

    if (pid < 0) {
        perror("fork failed");
        exit(1);
    }

    if (pid == 0) {
        // Child process: execute the test function
        test_func();
        // If it returns, the protection failed
        printf("[%s] Child process finished normally. Protection FAILED!\n", test_name);
        exit(0);
    } else {
        // Parent process: wait for child and check status
        int status;
        waitpid(pid, &status, 0);

        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            printf("[%s] Child terminated by signal %d (%s).\n", 
                   test_name, sig, strsignal(sig));
            if (sig == expected_signal) {
                printf("[%s] Protection SUCCESSFUL! Blocked by hardware trap.\n", test_name);
            } else {
                printf("[%s] Protection FAILED! Expected signal %d, but got %d.\n", 
                       test_name, expected_signal, sig);
            }
        } else {
            printf("[%s] Child did not terminate via signal. Protection FAILED!\n", test_name);
        }
    }
}

// ---------------------------------------------------------
// TEST 1: BKR (Batched Key-Rotation) UAF Protection Test
// ---------------------------------------------------------
void test_bkr_uaf(void) {
    kage_init();

    printf("[BKR Test] Allocating blocks to fill pool 0...\n");
    char* ptr = (char*)kage_malloc(BLOCK_SIZE);
    if (!ptr) {
        printf("[BKR Test] Initial allocation failed!\n");
        exit(1);
    }
    strcpy(ptr, "SensitiveData");
    printf("[BKR Test] Successfully wrote to block: %s\n", ptr);

    // Allocate the rest of pool 0
    for (int i = 1; i < BLOCKS_PER_PAGE; i++) {
        kage_malloc(BLOCK_SIZE);
    }

    // Free ptr
    kage_free(ptr);

    printf("[BKR Test] Allocating to force rotation to pool 1...\n");
    // Allocate two blocks: one to fill the freed ptr slot, one to force rotation
    kage_malloc(BLOCK_SIZE);
    kage_malloc(BLOCK_SIZE);

    // Now attempt to read the quarantined dangling pointer
    printf("[BKR Test] Dereferencing dangling pointer to quarantined page (expecting SIGSEGV)...\n");
    char leak = ptr[0]; // Accessing quarantined page
    
    // Should not reach here
    printf("[BKR Test] Critical Failure: Accessed quarantined pointer without fault! Read: %c\n", leak);
    exit(0);
}

// ---------------------------------------------------------
// TEST 2: TIMP (Thread-Isolated Metadata Partitioning) Test
// ---------------------------------------------------------
void test_timp_isolation(void) {
    kage_init();

    printf("[TIMP Test] Initializing metadata for Thread 0 and Thread 1...\n");
    kage_thread_init(0);
    kage_thread_init(1);

    // In a real application, Thread 1 would disable Key 15 of Thread 0.
    // In our test, Thread 0 tries to modify Thread 1's metadata
    verify_cross_thread_metadata(1);
    
    exit(0);
}

// ---------------------------------------------------------
// TEST 3: RICCG (Register-Isolated Cryptographic Call Gates) Test
// ---------------------------------------------------------
void test_riccg_rop(void) {
    kage_init();

    // Call gate with incorrect token
    simulate_rop_attack(0);
    
    exit(0);
}

// ---------------------------------------------------------
// Main Test Runner
// ---------------------------------------------------------
int main(int argc, char* argv[]) {
    if (argc > 1) {
        if (strcmp(argv[1], "bkr") == 0) {
            run_isolated_test("Batched Key-Rotation (BKR) - Temporal Safety", test_bkr_uaf, SIGSEGV);
        } else if (strcmp(argv[1], "timp") == 0) {
            run_isolated_test("Thread-Isolated Metadata Partitioning (TIMP)", test_timp_isolation, SIGSEGV);
        } else if (strcmp(argv[1], "riccg") == 0) {
            run_isolated_test("Register-Isolated Cryptographic Call Gates (RICCG)", test_riccg_rop, SIGILL);
        } else if (strcmp(argv[1], "--raw-bkr") == 0) {
            test_bkr_uaf();
        } else if (strcmp(argv[1], "--raw-timp") == 0) {
            test_timp_isolation();
        } else if (strcmp(argv[1], "--raw-riccg") == 0) {
            test_riccg_rop();
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[1]);
            return 1;
        }
        return 0;
    }

    printf("=========================================================\n");
    printf("        KageAlloc Cybersecurity Mitigation Test Suite    \n");
    printf("=========================================================\n");

    // Test BKR (Should trigger SIGSEGV)
    run_isolated_test("Batched Key-Rotation (BKR) - Temporal Safety", test_bkr_uaf, SIGSEGV);

    // Test TIMP (Should trigger SIGSEGV / Protection Key Fault)
    run_isolated_test("Thread-Isolated Metadata Partitioning (TIMP)", test_timp_isolation, SIGSEGV);

    // Test RICCG (Should trigger SIGILL due to UD2 instructions)
    run_isolated_test("Register-Isolated Cryptographic Call Gates (RICCG)", test_riccg_rop, SIGILL);

    printf("\n=== All Tests Evaluated ===\n");
    return 0;
}
