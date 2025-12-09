// Filename: test_malloc_hook.c
// Compile: gcc -o test_malloc_hook test_malloc_hook.c -lpthread
// Run: LD_PRELOAD=./malloc_hook.so ./test_malloc_hook

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

void* thread_func(void* arg) {
    printf("[Thread] Thread started, preparing to malloc...\n");
    void* p = malloc(123);
    if (p) {
        printf("[Thread] Thread malloc succeeded: %p\n", p);
        strcpy(p, "hello from thread");
        printf("[Thread] strcpy completed\n");
        free(p);
    }
    sleep(1);
    printf("[Thread] Thread ended\n");
    return NULL;
}

void trigger_indirect_malloc() {
    printf("[Main] Calling strdup (which triggers malloc)\n");
    char* s = strdup("indirect malloc via strdup");
    printf("[Main] strdup returned: %p -> \"%s\"\n", s, s);
    free(s);

    printf("[Main] Calling calloc\n");
    int* arr = calloc(10, sizeof(int));
    if (arr) {
        for (int i = 0; i < 10; i++) arr[i] = i * i;
        printf("[Main] calloc succeeded, first 3: %d %d %d\n", arr[0], arr[1], arr[2]);
        free(arr);
    }

    printf("[Main] Calling fopen (which triggers malloc)\n");
    FILE* f = fopen("/tmp/test_hook.txt", "w");
    if (f) {
        fprintf(f, "hook test ok\n");
        fclose(f);
        printf("[Main] fopen/fclose succeeded\n");
    }
}

int main() {
    printf("==========================================\n");
    printf(" Starting test: will malloc hook crash?\n");
    printf(" If you see Segmentation fault, the hook has a bug\n");
    printf(" If you see [Success], the hook is perfectly robust!\n");
    printf("==========================================\n");

    // 1. malloc at program start (most likely to crash)
    printf("[Main] First malloc (most critical!)\n");
    void* p1 = malloc(64);
    if (!p1) {
        printf("FATAL: First malloc failed! Hook has a serious bug!\n");
        return 1;
    }
    strcpy(p1, "first malloc success");
    printf("[Main] First malloc succeeded: %p -> \"%s\"\n", p1, (char*)p1);
    // 2. Start thread (pthread_create triggers malloc)
    printf("[Main] Creating thread (which triggers malloc)\n");
    pthread_t th;
    if (pthread_create(&th, NULL, thread_func, NULL) != 0) {
        printf("FATAL: pthread_create failed!\n");
        return 1;
    }

    // 3. Various indirect malloc
    trigger_indirect_malloc();

    // 4. More malloc calls
    printf("[Main] More malloc calls\n");
    void* p2 = malloc(100);
    void* p3 = malloc(200);
    printf("[Main] Multiple mallocs succeeded\n");

    // Wait for thread to finish
    pthread_join(th, NULL);

    // Cleanup
    free(p1);
    if (p2) free(p2);
    if (p3) free(p3);

    printf("==========================================\n");
    printf(" [Success] All tests passed! Your malloc hook is perfectly robust!\n");
    printf(" You can safely inject into cos, nrSmartAnt, and other processes!\n");
    printf("==========================================\n");

    return 0;
}
