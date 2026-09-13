//go:build ignore
#include "../common/vmlinux.h"
#include "../common/types.h"

#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_LRU_HASH 10

#define SEC(NAME) __attribute__((section(NAME), used))

// Helper function declarations
static long (*bpf_probe_read_user_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 114;
static __u64 (*bpf_ktime_get_ns)(void) = (void *) 5;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *) 14;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *) 80;
static long (*bpf_get_current_comm)(void *buf, __u32 size_of_buf) = (void *) 16;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *) 131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *) 132;
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;

// Ring buffer for streaming events from kernel to userspace Go
struct {
    __u32 type;
    __u32 max_entries;
} events SEC(".maps") = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 1 << 24, // 16 MB ring buffer
};

// Monitored cgroups filter map (keyed by cgroup_id)
struct {
    __u32 type;
    __u32 max_entries;
    __u32 key_size;
    __u32 value_size;
} monitored_cgroups SEC(".maps") = {
    .type = BPF_MAP_TYPE_HASH,
    .max_entries = 10240,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u32),
};

static __always_inline int is_monitored_cgroup(__u64 cgroup_id) {
    void *val = bpf_map_lookup_elem(&monitored_cgroups, &cgroup_id);
    return val != 0;
}

// Syscall enter tracepoint hook
SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (!is_monitored_cgroup(cgroup_id)) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    e->timestamp = bpf_ktime_get_ns();
    e->cgroup_id = cgroup_id;
    e->pid = pid;
    e->ppid = 0;
    e->type = EVENT_EXEC; // generic default
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->data[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Openat tracepoint hook (capture sensitive file paths)
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_sys_openat(struct trace_event_raw_sys_enter *ctx) {
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (!is_monitored_cgroup(cgroup_id)) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    e->timestamp = bpf_ktime_get_ns();
    e->cgroup_id = cgroup_id;
    e->pid = pid;
    e->ppid = 0;
    e->type = EVENT_OPENAT;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    const char *filename_ptr = (const char *)ctx->args[1];
    if (filename_ptr) {
        bpf_probe_read_user_str(&e->data, sizeof(e->data), filename_ptr);
    } else {
        e->data[0] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Connect tracepoint hook (capture destination socket activity)
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_sys_connect(struct trace_event_raw_sys_enter *ctx) {
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (!is_monitored_cgroup(cgroup_id)) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    e->timestamp = bpf_ktime_get_ns();
    e->cgroup_id = cgroup_id;
    e->pid = pid;
    e->ppid = 0;
    e->type = EVENT_CONNECT;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->data[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Setns / Unshare tracepoint hooks (capture namespace pivots)
SEC("tracepoint/syscalls/sys_enter_setns")
int trace_sys_setns(struct trace_event_raw_sys_enter *ctx) {
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (!is_monitored_cgroup(cgroup_id)) {
        return 0;
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    e->timestamp = bpf_ktime_get_ns();
    e->cgroup_id = cgroup_id;
    e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    e->type = EVENT_SETNS;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->data[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unshare")
int trace_sys_unshare(struct trace_event_raw_sys_enter *ctx) {
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (!is_monitored_cgroup(cgroup_id)) {
        return 0;
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    e->timestamp = bpf_ktime_get_ns();
    e->cgroup_id = cgroup_id;
    e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    e->type = EVENT_UNSHARE;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->data[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
