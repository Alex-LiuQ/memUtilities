// Filename: leak_test.c
// Compile: gcc -o leak_test leak_test.c -lpthread
// Test method:
//    LD_PRELOAD=./libmalloc_hook.so ./leak_test

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

#define LEAK_SIZE     24        // Every leak is 24 bytes
#define LEAK_INTERVAL 3         // Leak every 3 seconds
#define START_DELAY   12        // No leak for the first 12 seconds (simulate initialization phase)

// Deliberate leak function (call stack will point here)
__attribute__((noinline))
void leak_memory(const char *type)
{
    void *p;
    if (strcmp(type, "malloc") == 0) {
        p = malloc(LEAK_SIZE);
    } else {
        p = calloc(1, LEAK_SIZE);   // Mix calloc to ensure hook can catch
    }

    if (p) {
        // Write some data to really occupy the memory (avoid optimization)
        memset(p, 0xAA, LEAK_SIZE);
        strcpy(p, "LEAKED MEMORY HERE");

        // Deliberately not freeing! This is a leak!
        // free(p);   ← Commented out = leak
    }

    // Prevent compiler from optimizing away p
    __asm__ volatile ("" : : "r,m"(p) : "memory");
}

// Leak thread: start leaking continuously after 12 seconds
void* leak_thread(void *arg)
{
    printf("[LeakThread] Started, waiting %d seconds before leaking...\n", START_DELAY);
    sleep(START_DELAY);

    printf("[LeakThread] Starting continuous leaking! Leaking %d bytes every %ds...\n", LEAK_SIZE, LEAK_INTERVAL);

    int count = 0;
    while (1) {
        count++;
        if (count % 2 == 1) {
            leak_memory("malloc");
            printf("[Leak %d] malloc(%d) leak @ %p\n", count, LEAK_SIZE, __builtin_return_address(0));
        } else {
            leak_memory("calloc");
            printf("[Leak %d] calloc(1,%d) leak @ %p\n", count, LEAK_SIZE, __builtin_return_address(0));
        }
        sleep(LEAK_INTERVAL);
    }
    return NULL;
}

int main()
{
    printf("==========================================\n");
    printf(" Memory leak test program started\n");
    printf(" No leaks for the first %d seconds (initialization phase)\n", START_DELAY);
    printf(" Starting at %d seconds: leaking %d bytes every %d seconds (from leak_memory())\n", 
           START_DELAY, LEAK_SIZE, LEAK_INTERVAL);
    printf(" Please test with your libmalloc_hook.so injection!\n");
    printf("==========================================\n");

    // Start leak thread
    pthread_t th;
    pthread_create(&th, NULL, leak_thread, NULL);

    // Main thread keeps running
    while (1) {
        sleep(10);
        // Occasionally do some normal allocations to simulate real load
        void *tmp = malloc(100);
        if (tmp) {
            strcpy(tmp, "normal alloc");
            free(tmp);
        }
    }

    return 0;
}
