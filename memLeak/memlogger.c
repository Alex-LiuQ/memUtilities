#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#define LOG_FILE        "/var/memlog.txt"
#define SLEEP_MINUTES   5

/* 需要重点关注的进程名列表（默认模式下只监控这些） */
static const char *focus_comm[] = {
    "nrSmartAnt",
    "cos",
    "power_managemen",
    NULL                     // 必须以 NULL 结尾
};

/* 基线记录结构（按 comm 保存第一次出现的内存值） */
typedef struct BaseInfo {
    char comm[64];
    long base_rss_anon_kb;   // 基线 RssAnon
    long base_vm_data_kb;    // 基线 VmData
    struct BaseInfo *next;
} BaseInfo;

static BaseInfo *baseline_head = NULL;
static int monitor_all = 0;      // 是否监控所有进程（-a 参数）

/* ========================= 工具函数 ========================= */
static void write_log(const char *msg)
{
    FILE *fp = fopen(LOG_FILE, "a");
    if (fp) {
        fprintf(fp, "%s\n", msg);
        fclose(fp);
    }
}

static int is_number(const char *s)
{
    while (*s) if (!isdigit(*s++)) return 0;
    return 1;
}

/* 查找或创建基线记录（按 comm） */
static BaseInfo *get_baseline(const char *comm)
{
    BaseInfo *p = baseline_head;
    while (p) {
        if (strcmp(p->comm, comm) == 0) return p;
        p = p->next;
    }
    /* 不存在则创建 */
    p = calloc(1, sizeof(BaseInfo));
    strncpy(p->comm, comm, sizeof(p->comm)-1);
    p->next = baseline_head;
    baseline_head = p;
    return p;
}

/* 读取 RssAnon（最准确的泄漏指标） */
static long read_rss_anon_kb(const char *pid_str)
{
    char path[128];
    snprintf(path, sizeof(path), "/proc/%s/status", pid_str);
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

/* 读取 VmData（次优指标） */
static long read_vm_data_kb(const char *pid_str)
{
    char path[128];
    snprintf(path, sizeof(path), "/proc/%s/status", pid_str);
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    long val = -1;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmData:", 7) == 0) {
            sscanf(line + 7, "%ld", &val);
            break;
        }
    }
    fclose(f);
    return val;
}

/* 读取进程名 */
static int read_comm(const char *pid_str, char *comm_out, size_t len)
{
    char path[128];
    snprintf(path, sizeof(path), "/proc/%s/comm", pid_str);
    FILE *f = fopen(path, "r");
    if (!f) {
        strncpy(comm_out, "unknown", len-1);
        return -1;
    }
    if (fgets(comm_out, len, f)) {
        comm_out[strcspn(comm_out, "\n")] = '\0';
    }
    fclose(f);
    return 0;
}

/* 判断进程是否在关注列表中 */
static int is_focus_process(const char *comm)
{
    if (monitor_all) return 1;               // -a 模式下全部关注
    for (int i = 0; focus_comm[i]; i++) {
        if (strcmp(comm, focus_comm[i]) == 0)
            return 1;
    }
    return 0;
}

/* ========================= 一次扫描 ========================= */
static void do_scan(void)
{
    static int loop = 0;
    DIR *dir = opendir("/proc");
    if (!dir) {
        perror("opendir /proc");
        return;
    }

    FILE *log = fopen(LOG_FILE, "a");
    if (!log) {
        perror("fopen " LOG_FILE);
        closedir(dir);
        return;
    }

    time_t now = time(NULL);
    char timestr[64];
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(log, "\n==== Scan #%d | %s | %s ====\n",
            ++loop, timestr, monitor_all ? "ALL PROCESSES" : "FOCUS LIST");

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (!is_number(ent->d_name)) continue;

        char pid_str[16];
        snprintf(pid_str, sizeof(pid_str), "%s", ent->d_name);

        char comm[64] = "unknown";
        read_comm(pid_str, comm, sizeof(comm));

        if (!is_focus_process(comm)) continue;   // 过滤

        long rss_anon = read_rss_anon_kb(pid_str);
        long vm_data  = read_vm_data_kb(pid_str);
        if (rss_anon < 0 || vm_data < 0) continue;

        BaseInfo *base = get_baseline(comm);

        /* 第一次见到该 comm，记录基线 */
        if (base->base_rss_anon_kb == 0) {
            base->base_rss_anon_kb = rss_anon;
            base->base_vm_data_kb  = vm_data;
        }

        long diff_anon = rss_anon - base->base_rss_anon_kb;
        long diff_data = vm_data  - base->base_vm_data_kb;

        fprintf(log, "PID=%-6s COMM=%-20s RssAnon=%6ld kB (%+4ld)  VmData=%6ld kB (%+4ld)",
                pid_str, comm, rss_anon, diff_anon, vm_data, diff_data);

        if (diff_anon > 128 || diff_data > 128) {
            fprintf(log, "  *** POSSIBLE MEMORY LEAK ***");
        } else if (diff_anon < -256 || diff_data < -256) {
            fprintf(log, "  [Memory dropped - possible restart]");
        }

        fprintf(log, "\n");
    }

    /* 附加系统 free 信息 */
    fprintf(log, "\n");
    fflush(log);
    system("free -k >> " LOG_FILE " 2>&1");
    fprintf(log, "==== End Scan #%d ====\n\n", loop);
    fclose(log);
    closedir(dir);
}

/* ========================= 主函数 ========================= */
int main(int argc, char *argv[])
{
    if (argc >= 2 && strcmp(argv[1], "-a") == 0) {
        monitor_all = 1;
    }

    char msg[128];
    time_t now = time(NULL);
    snprintf(msg, sizeof(msg),
             "\n\n==== Memory Monitor START | %s | Mode: %s ====\n",
             ctime(&now), monitor_all ? "ALL PROCESSES (-a)" : "FOCUS LIST");
    write_log(msg);

    while (1) {
        do_scan();
        sync();
        sleep(SLEEP_MINUTES * 60);
    }

    return 0;   // 永远不会执行到这里
}