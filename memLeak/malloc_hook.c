// malloc_hook_cos_v4.c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <sys/types.h>
#include <fcntl.h>

/*
  Complete malloc hook for OpenWrt/musl environment.

  Features:
  - Hooks: malloc, free, calloc, realloc, posix_memalign
  - Safety: enter/leave hooks with thread-local reentrancy guard
  - Safe initialization via dlopen(libc) then dlsym
  - Record simple caller info (two-level return addresses)
  - Periodic report thread prints report to log in your original format,
    using stack buffers + write() to avoid triggering allocation inside hooks.
  - Signal handler prints final report.
*/

/* Config */
#define LOG_FILE_PATH "/var/memhook.log"
#define MAX_LEAK_TRACK 20000
#define LOG_MAX_SIZE (1024 * 1024 * 10)

#define INIT_TIME_SEC           120  /* time to wait for baseline init */
#define REPORT_INTERVAL_SEC     60 /* hourly; adjust for testing if needed */

// Filter keywords (process name)
static const char* filter_keywords[] = {
    "sh", "ash", "busybox", "grep", "ls", "ps", "uci",
    "iptables", "ip6tables", "ebtables", "ip", "insmod",
    "mkdir", "switch", "pidof", "zebra", "dibbler", "dhcpd", "dhcpc",
    "upnpd", "mknod", "igmpd", "rc.router", "iptables-stop",
    "hostd", "flowstat", "tr143d", "xmpp", "ntpc", "dyndns",
    "noipdns", "dnsProxy", "ln", "unzip", "killall", "md5sum",
    "dnsmasq", "power_managemen", "tp1905cliA", "mobile_cli",
    "[", "sed", "awk", "ifconfig", "watchdog", "wpa_cli", "brctl",
    "tcpdump", "swconfig", "hostapd_cli", "mwctl", "cat", "echo",
    "touch", "iwpriv", "lock", "wifi", "lock", "tmpd", "rm", "pfcached",
    "dropbearkey", "httpd", "touch", "setkey", "dropbear", "diagTool",
    "cloud-brd", "cloud_client", "iwpriv", "wportalctrl", "netstat",
    "gms", "nrd", "mapBhOpt", "mapAgent", "mapController", "qoeStatisticsHa",
    "wanconnd2", "obuspa", "exe", "slic_demo", "libmodem-afe-ct",
    "audio-ctrl-serv", "speech_daemon", "wpa_cli", "cut", "chmod",
    "cp", "hostapd", "wpa_supplicant", "tr", "tdpd", "amixer",
    "cwmp", "mobile", "mobiledog",
    NULL
};

/* ----- Real libc function pointers ----- */
static void* (*real_malloc)(size_t) = NULL;
static void* (*real_free)(void*) = NULL;
static void* (*real_calloc)(size_t, size_t) = NULL;
static void* (*real_realloc)(void*, size_t) = NULL;
static int   (*real_posix_memalign)(void **, size_t, size_t) = NULL;

/* ----- Thread-local and init guards ----- */
static __thread int in_hook = 0;                 /* thread-local reentrancy flag */
static volatile int init_in_progress = 0;
static pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ENTER/LEAVE macros keep previous state to restore safely */
#define ENTER_HOOK() \
    int _hook_prev = in_hook; \
    in_hook = 1;

#define LEAVE_HOOK() \
    in_hook = _hook_prev;

/* ----- Global statistics ----- */
static volatile uint64_t total_requested_bytes = 0;
static volatile int64_t  current_heap_bytes   = 0;
static volatile uint64_t peak_bytes           = 0;
static volatile uint64_t alloc_count = 0;
static volatile uint64_t free_count  = 0;
static time_t start_time = 0;

/* ----- Leak tracking ----- */
#define MAX_CALLER_DEPTH 8
struct leak_entry {
    void *ptr;
    size_t size;
    void *caller[MAX_CALLER_DEPTH];
    uint64_t ts;     // Allocation time (milliseconds)
    int active;      // 1=active, 0=freed
    int printed;    // 1=reported, 0=not reported
};
struct leak_entry *leak_track = NULL;
static volatile int leak_count = 0;
static pthread_mutex_t leak_mutex = PTHREAD_MUTEX_INITIALIZER;


/* ----- Logging ----- */
static FILE* log_file = NULL;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static int log_index = 0;

/* Process info */
static char proc_name[64] = "unknown";
static pid_t cached_pid = 0;

/* Init baseline */
static volatile int is_initialized = 0;
static volatile int64_t init_net_bytes = 0;

/* ----- Utility: usable size (musl/glibc compatibility) ----- */
extern size_t malloc_usable_size(void*) __attribute__((weak));
extern size_t __malloc_usable_size(void*) __attribute__((weak));
static inline size_t get_usable_size(void *p) {
    if (!p) return 0;
    if (malloc_usable_size) return malloc_usable_size(p);
    if (__malloc_usable_size) return __malloc_usable_size(p);
    return 0;
}

/* ----- Rotate log if too big ----- */
static void rotate_log_if_needed(void) {
    if (!log_file) return;
    struct stat st;
    if (fstat(fileno(log_file), &st) == 0 && st.st_size > LOG_MAX_SIZE) {
        fclose(log_file);
        char newname[128];
        snprintf(newname, sizeof(newname), LOG_FILE_PATH ".%d", ++log_index);
        rename(LOG_FILE_PATH, newname);
        log_file = fopen(LOG_FILE_PATH, "a");
        if (log_file) setvbuf(log_file, NULL, _IOLBF, 0);
    }
}

/* Safe formatted logging (uses vfprintf on already-opened FILE).
   vfprintf typically does not allocate; but to be extra safe we use a stack buffer + write for critical reports. */
static void log_printf_stack(const char *fmt, ...) {
    if (!log_file) return;
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) {
        if (n > (int)sizeof(buf)) n = sizeof(buf);
        write(fileno(log_file), buf, n);
        rotate_log_if_needed();
    }
}

// -------------------- Process filter --------------------
static int should_skip_process(char *name)
{
    if(name == NULL || name[0] == '\0')
    {
        return 1;
    }

    for (int i = 0; filter_keywords[i]; i++) {
        if (strstr(name, filter_keywords[i])) {
            return 1; // skip
        }
    }
    return 0;
}

static inline int get_caller_stack(void **callers, int max_depth) {
    void** bp = (void**) __builtin_frame_address(0);
    void** bp_prev = (void**) bp[0];
    int depth = 0;
    while (bp_prev && depth < max_depth) {
        callers[depth++] = bp_prev[1];
        bp_prev = (void**) bp_prev[0];
    }
    return depth;
}

/* Read RssAnon (most accurate leak metric) */
static long read_rss_anon_kb(int pid)
{
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    long val = -1;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "RssAnon:", 8) == 0) {
            sscanf(line + 8, "%ld", &val);
            break;
        }
    }
    fclose(f);
    return val;
}

static uint64_t now_ms()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000) + ts.tv_nsec / 1000000;
}

/* ----- Safe init hook: resolve libc symbols ----- */
static void safe_init_hook(void) {
    /* fast path */
    if (real_malloc && real_free && (real_calloc || real_realloc)) return;

    /* ensure single-thread init */
    if (__sync_lock_test_and_set(&init_in_progress, 1)) {
        /* another thread is initializing; wait briefly */
        int spins = 0;
        while (!(real_malloc && real_free) && spins++ < 100000) {
            /* busy wait */
        }
        __sync_lock_release(&init_in_progress);
        return;
    }

    /* try to dlopen common libc names */
    void *h = NULL;
    const char *names[] = {"libc.so.6", "libc.so", "libc.musl-x86_64.so.1", NULL};
    for (int i = 0; names[i]; i++) {
        h = dlopen(names[i], RTLD_NOW | RTLD_LOCAL);
        if (h) break;
    }
    if (h) {
        real_malloc = dlsym(h, "malloc");
        real_free = dlsym(h, "free");
        real_calloc = dlsym(h, "calloc");
        real_realloc = dlsym(h, "realloc");
        real_posix_memalign = dlsym(h, "posix_memalign");
    } else {
        /* fallback to RTLD_NEXT if libc handle not found */
        real_malloc = dlsym(RTLD_NEXT, "malloc");
        real_free = dlsym(RTLD_NEXT, "free");
        real_calloc = dlsym(RTLD_NEXT, "calloc");
        real_realloc = dlsym(RTLD_NEXT, "realloc");
        real_posix_memalign = dlsym(RTLD_NEXT, "posix_memalign");
    }

    __sync_lock_release(&init_in_progress);
}

/* ----- Record caller (safe): store two return addresses ----- */
static void record_caller_safe(void *ptr, size_t size) {
    if (!ptr || size < 1) return;
    /* Only record after init to reduce noise */
    if (!is_initialized) return;

    pthread_mutex_lock(&leak_mutex);
    if (leak_count < MAX_LEAK_TRACK) {
        int idx = leak_count++;
        leak_track[idx].ptr = ptr;
        leak_track[idx].size = size;
        leak_track[idx].ts = now_ms();
        leak_track[idx].active = 1;
        get_caller_stack(leak_track[idx].caller, MAX_CALLER_DEPTH);
        // void** bp = (void**) __builtin_frame_address(0);
        // void** bp_prev = (void**) bp[0];
        // if (bp_prev) {
        //     for (int i = 0; i < MAX_CALLER_DEPTH && bp_prev; i++) {
        //         leak_track[idx].caller[i] = bp_prev[1];
        //         bp_prev = (void**) bp_prev[0];
        //     }
        // }
    }
    pthread_mutex_unlock(&leak_mutex);
}

/* ----- Watermark (low-frequency) ----- */
static void print_watermark(const char* op, void* ptr, size_t size) {
    if (!is_initialized) return;
    static volatile uint64_t counter = 0;
    if ((counter++) % 2000 != 0) return;

    int64_t net_delta_kb = (current_heap_bytes / 1024) - (init_net_bytes / 1024);
    if (net_delta_kb < 512) return;

    uint64_t total_kb = total_requested_bytes / 1024;
    uint64_t peak_kb  = peak_bytes / 1024;

    /* Use stack buffer and write to log_file fd */
    char buf[512];
    void *caller[MAX_CALLER_DEPTH];
    get_caller_stack(caller, MAX_CALLER_DEPTH);
    int rss_anon_kb = read_rss_anon_kb(cached_pid);
    int n = snprintf(buf, sizeof(buf),
                     "[WATER] PID=%d PROC=%s Total=%lluKB NetGrow=%lldKB RssAnon:%lld Peak=%lluKB Alloc/Free/Diff=%llu/%llu/%lld | %s %p sz=%-5zu |"
                     "CallerStack= %p, %p, %p, %p, %p, %p, %p, %p\n",
                     cached_pid,
                     proc_name,
                     (unsigned long long)total_kb,
                     (long long)net_delta_kb,
                     (long long)rss_anon_kb,
                     (unsigned long long)peak_kb,
                     (unsigned long long)alloc_count,
                     (unsigned long long)free_count,
                     (long long)(alloc_count - free_count),
                     op, ptr, size,
                     caller[0], caller[1], caller[2], caller[3],
                     caller[4], caller[5], caller[6], caller[7]);
    if (n > 0 && log_file) {
        write(fileno(log_file), buf, n);
        rotate_log_if_needed();
    }
}

/* ----- Hook implementations ----- */

/* malloc hook */
void *malloc(size_t size) {
    /* If we are re-entering, call the real malloc if available */
    if (in_hook) {
        if (real_malloc) return real_malloc(size);
        return NULL;
    }

    ENTER_HOOK();
    safe_init_hook();
    if (!real_malloc) { LEAVE_HOOK(); return NULL; }

    void *p = real_malloc(size);
    if (p) {
        __sync_fetch_and_add(&total_requested_bytes, (uint64_t)size);
        __sync_fetch_and_add(&alloc_count, 1);

        /* Heuristic: if caller address is in libc range, treat as internal */
        void *caller = __builtin_return_address(0);
        int is_libc_internal = 0;
        uintptr_t caddr = (uintptr_t)caller;
        if (caddr >= 0x7f000000ULL && caddr < 0x80000000ULL) is_libc_internal = 1;

        if (!is_libc_internal) {
            __sync_fetch_and_add(&current_heap_bytes, (int64_t)size);

            /* update peak */
            uint64_t cur = (uint64_t) current_heap_bytes;
            uint64_t old = peak_bytes;
            while (cur > old && !__sync_bool_compare_and_swap(&peak_bytes, old, cur)) {
                old = peak_bytes;
            }

            record_caller_safe(p, size);
            print_watermark("M", p, size);
        }
    }

    LEAVE_HOOK();
    return p;
}

/* free hook */
void free(void *ptr) {
    if (!ptr) return;

    if (in_hook) {
        if (real_free) real_free(ptr);
        return;
    }

    ENTER_HOOK();
    safe_init_hook();
    if (!real_free) { LEAVE_HOOK(); return; }

    size_t usable = get_usable_size(ptr);
    if (usable == 0) usable = 0;

    real_free(ptr);
    __sync_fetch_and_add(&free_count, 1);

    if (usable >= 64) {
        __sync_fetch_and_sub(&current_heap_bytes, (int64_t)usable);
    }

    /* remove from leak track if present */
    pthread_mutex_lock(&leak_mutex);
    for (int i = 0; i < leak_count; i++) {
        if (leak_track[i].ptr == ptr) {
            if(leak_track[i].active) {
                leak_track[i].active = 0;
            }
            if (i != leak_count - 1) {
                memmove(&leak_track[i], &leak_track[i+1], sizeof(leak_track[0]) * (leak_count - i - 1));
            }
            leak_count--;
            break;
        }
    }
    pthread_mutex_unlock(&leak_mutex);

    print_watermark("F", ptr, 0);
    LEAVE_HOOK();
}

/* calloc hook */
void *calloc(size_t nmemb, size_t size) {
    size_t total = nmemb * size;
    if (in_hook) {
        if (real_calloc) return real_calloc(nmemb, size);
        if (!real_malloc) safe_init_hook();
        if (!real_malloc) return NULL;
        void *p = real_malloc(total);
        if (p) memset(p, 0, total);
        return p;
    }

    ENTER_HOOK();
    safe_init_hook();
    if (!real_calloc && !real_malloc) { LEAVE_HOOK(); return NULL; }

    void *p = real_calloc ? real_calloc(nmemb, size) : real_malloc(total);
    if (p && !real_calloc) memset(p, 0, total);

    if (p) {
        __sync_fetch_and_add(&total_requested_bytes, (uint64_t)total);
        __sync_fetch_and_add(&alloc_count, 1);

         /* Heuristic: if caller address is in libc range, treat as internal */
        void *caller = __builtin_return_address(0);
        int is_libc_internal = 0;
        uintptr_t caddr = (uintptr_t)caller;
        if (caddr >= 0x7f000000ULL && caddr < 0x80000000ULL) is_libc_internal = 1;

        if (!is_libc_internal) {
            __sync_fetch_and_add(&current_heap_bytes, (int64_t)total);

            record_caller_safe(p, total);
            print_watermark("C", p, total);
        }

        // if (total >= 64) {
        //     __sync_fetch_and_add(&current_heap_bytes, (int64_t)total);
        //     record_caller_safe(p, total);
        //     print_watermark("C", p, total);
        // }
    }
    LEAVE_HOOK();
    return p;
}

/* realloc hook */
void *realloc(void *ptr, size_t size) {
    if (in_hook) {
        if (real_realloc) return real_realloc(ptr, size);
        return NULL;
    }

    ENTER_HOOK();
    safe_init_hook();
    if (!real_realloc) { LEAVE_HOOK(); return NULL; }

    size_t old_size = ptr ? get_usable_size(ptr) : 0;
    void *np = real_realloc(ptr, size);

    if (np) {
        if (size > old_size && size - old_size >= 64) {
            __sync_fetch_and_add(&current_heap_bytes, (int64_t)(size - old_size));
        } else if (old_size > size && old_size >= 64) {
            __sync_fetch_and_sub(&current_heap_bytes, (int64_t)(old_size - size));
        }
        print_watermark("R", np, size);
    }

    LEAVE_HOOK();
    return np;
}

/* posix_memalign hook */
int posix_memalign(void **memptr, size_t alignment, size_t size) {
    if (in_hook) {
        if (real_posix_memalign) return real_posix_memalign(memptr, alignment, size);
        return -1;
    }

    ENTER_HOOK();
    safe_init_hook();
    if (!real_posix_memalign) { LEAVE_HOOK(); return -1; }

    int r = real_posix_memalign(memptr, alignment, size);
    if (r == 0 && memptr && *memptr) {
        __sync_fetch_and_add(&total_requested_bytes, (uint64_t)size);
        __sync_fetch_and_add(&alloc_count, 1);

       /* Heuristic: if caller address is in libc range, treat as internal */
        void *caller = __builtin_return_address(0);
        int is_libc_internal = 0;
        uintptr_t caddr = (uintptr_t)caller;
        if (caddr >= 0x7f000000ULL && caddr < 0x80000000ULL) is_libc_internal = 1;

        if (!is_libc_internal) {
            __sync_fetch_and_add(&current_heap_bytes, (int64_t)size);

            record_caller_safe(*memptr, size);
            print_watermark("PM", *memptr, size);
        }

        // if (size >= 64) {
        //     __sync_fetch_and_add(&current_heap_bytes, (int64_t)size);
        //     record_caller_safe(*memptr, size);
        //     print_watermark("PM", *memptr, size);
        // }
    }
    LEAVE_HOOK();
    return r;
}

/* ----- Periodic reporting thread: follow old format, avoid allocations ----- */
static void* report_thread_func(void *arg) {
    (void)arg;

    while (1) {
        sleep(REPORT_INTERVAL_SEC);

        /* Build report in stack buffer to avoid any heap use */
        char buf[8192];
        int off = 0;

        /* Time */
        time_t now = time(NULL);
        char time_str[64] = "UNKNOWN";
        struct tm tmv;
        if (localtime_r(&now, &tmv)) {
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tmv);
        }

        /* Running time */
        time_t elapsed = now - start_time;
        int hours = elapsed / 3600;
        int mins  = (elapsed % 3600) / 60;
        int secs  = elapsed % 60;

        /* Current stats snapshot (read atomically-ish) */
        uint64_t total_kb = (uint64_t)(total_requested_bytes / 1024);
        int64_t current_net_kb = (int64_t)(current_heap_bytes / 1024);
        int64_t net_delta_kb = (int64_t)((current_heap_bytes - init_net_bytes) / 1024);
        uint64_t peak_kb = (uint64_t)(peak_bytes / 1024);
        uint64_t a_count = (uint64_t)alloc_count;
        uint64_t f_count = (uint64_t)free_count;
        int leaks = leak_count;
        pid_t pid = cached_pid ? cached_pid : getpid();

        /* Prepare header block exactly like old format */
        off += snprintf(buf + off, sizeof(buf) - off,
                        "\n================== PERIODIC MEMORY REPORT ==================\n"
                        "Report Time   : %s\n"
                        "Running Time  : %dh %dm %ds\n"
                        "PID           : %5d\n"
                        "Process       : %-15s\n"
                        "Total Req     : %8llu KB\n"
                        "Net Mem       : %8lld KB\n"
                        "Post-Init Growth : %8lld KB\n"
                        "Peak Mem      : %8llu KB\n"
                        "Alloc/Free    : %8llu / %8llu (diff:%lld)\n"
                        "Current tracked leaks : %d / %d\n",
                        time_str,
                        hours, mins, secs,
                        (int)pid, proc_name,
                        (unsigned long long)total_kb,
                        (long long)current_net_kb,
                        (long long)net_delta_kb,
                        (unsigned long long)peak_kb,
                        (unsigned long long)a_count, (unsigned long long)f_count,
                        (long long)(a_count - f_count),
                        leaks, MAX_LEAK_TRACK);

        /* Write header to log file descriptor */
        if (log_file) {
            int fd = fileno(log_file);
            if (off > 0) write(fd, buf, off);
        } else {
            /* fallback to stderr */
            if (off > 0) write(2, buf, off);
        }

        /* If suspicious growth, dump leaks */
        // if (net_delta_kb > 512 && leaks > 0) {
        if (net_delta_kb > 16) {
            /* Print notice */
            char head2[256];
            int n2 = snprintf(head2, sizeof(head2),
                              "\nSuspicious growth detected! Potential leaks (Top %d):\n",
                              leaks);
            if (log_file) write(fileno(log_file), head2, n2);
            else write(2, head2, n2);

            /* Iterate leak_track and print each */
            pthread_mutex_lock(&leak_mutex);
            int to_show = leaks;
            if (to_show > MAX_LEAK_TRACK) to_show = MAX_LEAK_TRACK;
            for (int i = 0; i < to_show; i++) {
                char one[512];
                if(!leak_track[i].active || leak_track[i].printed) {
                    continue;
                }
                int o = snprintf(one, sizeof(one),
                                 "Leak #%03d: %6zu KB at %p, alive:%1lu ms, callstack: ",
                                 i+1, leak_track[i].size / 1024, leak_track[i].ptr, now_ms() - leak_track[i].ts);
                if (log_file) write(fileno(log_file), one, o);
                else write(2, one, o);

                /* Print detailed call stack */
                for(int j = 0; j < MAX_CALLER_DEPTH; j++) {
                    void *c = leak_track[i].caller[j];
                    if (!c) break;
                    char ln[128];
                    int lnlen = snprintf(ln, sizeof(ln), "    #[%1d]: %p", j, c);
                    if (log_file) write(fileno(log_file), ln, lnlen);
                    else write(2, ln, lnlen);
                }
                const char *newline = "\n";
                if (log_file) write(fileno(log_file), newline, strlen(newline));
                else write(2, newline, strlen(newline));

                leak_track[i].printed = 1;
            }

            /* Reset leak tracking */            
            // char reset_info[64];
            // n2 = snprintf(reset_info, sizeof(reset_info),
            //                   "\n**************** reset leak_count:%d & leak_track\n", leak_count);
            // if (log_file) write(fileno(log_file), reset_info, n2);
            // else write(2, reset_info, n2);

            // memset(leak_track, 0, sizeof(leak_track));
            // leak_count = 0;

            pthread_mutex_unlock(&leak_mutex);
        } else {
            const char *msg = "\nNo significant growth in this period.\n";
            if (log_file) write(fileno(log_file), msg, strlen(msg));
            else write(2, msg, strlen(msg));
        }

        const char *footer = "========================================================\n\n";
        if (log_file) write(fileno(log_file), footer, strlen(footer));
        else write(2, footer, strlen(footer));
    } /* while */
    return NULL;
}

/* ----- init-end thread: set baseline after short delay ----- */
static void* init_end_thread_func(void *arg) {
    (void)arg;
    sleep(INIT_TIME_SEC); /* initialization phase */
    init_net_bytes = current_heap_bytes;
    is_initialized = 1;
    log_printf_stack("[InitEnd] Initialization complete. Baseline set: %lld bytes\n", (long long)init_net_bytes);
    return NULL;
}

/* ----- signal handler: print final report ----- */
static void sigterm_handler(int sig) {
    (void)sig;
    /* Use stack buffer to format final report */
    char buf[1024];
    int off = snprintf(buf, sizeof(buf),
                       "\n================== FINAL MEMORY REPORT ON TERM ==================\n"
                       "PID        : %5d\n"
                       "Process    : %-15s\n"
                       "Total Req  : %8llu KB\n"
                       "Net Mem    : %8lld KB\n"
                       "Post-Init Growth: %8lld KB\n"
                       "Peak Mem   : %8llu KB\n"
                       "Alloc/Free : %8llu / %8llu\n",
                       (int)(cached_pid ? cached_pid : getpid()),
                       proc_name,
                       (unsigned long long)(total_requested_bytes / 1024),
                       (long long)(current_heap_bytes / 1024),
                       (long long)((current_heap_bytes - init_net_bytes) / 1024),
                       (unsigned long long)(peak_bytes / 1024),
                       (unsigned long long)alloc_count,
                       (unsigned long long)free_count);
    if (log_file) write(fileno(log_file), buf, off);
    else write(2, buf, off);

    /* Optionally list leaks */
    if (leak_count > 0) {
        char head[128];
        int n = snprintf(head, sizeof(head), "\nPotential leaks (Top %d):\n", leak_count);
        if (log_file) write(fileno(log_file), head, n);
        else write(2, head, n);

        pthread_mutex_lock(&leak_mutex);
        for (int i = 0; i < leak_count; i++) {
            char one[256];
            int o = snprintf(one, sizeof(one), "Leak #%02d: %6zu KB at %p\n", i+1, leak_track[i].size / 1024, leak_track[i].ptr);
            if (log_file) write(fileno(log_file), one, o);
            else write(2, one, o);
        }
        pthread_mutex_unlock(&leak_mutex);
    }

    _exit(0);
}

/* ----- constructor setup ----- */
__attribute__((constructor))
static void setup(void) {
    start_time = time(NULL);
    cached_pid = getpid();

    /* read process name */
    FILE *f = fopen("/proc/self/comm", "r");
    if (f) {
        if (fgets(proc_name, sizeof(proc_name), f)) {
            size_t n = strlen(proc_name);
            if (n && proc_name[n-1] == '\n') proc_name[n-1] = '\0';
        }
        fclose(f);
    }

    if (should_skip_process(proc_name)) return;

    /* install signal handlers */
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);

    leak_track = (struct leak_entry*)calloc(MAX_LEAK_TRACK, sizeof(struct leak_entry));

    /* safe init early */
    safe_init_hook();

    /* open log file early */
    log_file = fopen(LOG_FILE_PATH, "a");
    if (log_file) {
        setvbuf(log_file, NULL, _IOLBF, 0);
        log_printf_stack("[MallocHook] Log opened: %s, pid:%d, procname:%s\n", LOG_FILE_PATH, cached_pid, proc_name);
    } else {
        /* fallback to stderr */
        write(2, "[MallocHook] Failed to open log file\n", 36);
    }

    /* spawn threads */
    pthread_t rpt, ini;
    pthread_create(&rpt, NULL, report_thread_func, NULL);
    pthread_detach(rpt);
    pthread_create(&ini, NULL, init_end_thread_func, NULL);
    pthread_detach(ini);
}
