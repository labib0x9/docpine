//go:build ignore
#include "../common/vmlinux.h"
#include "../common/types.h"

#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_MAP_TYPE_HASH 1

#define SEC(NAME) __attribute__((section(NAME), used))

static __u64 (*bpf_ktime_get_ns)(void) = (void *) 5;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *) 14;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *) 80;
static long (*bpf_get_current_comm)(void *buf, __u32 size_of_buf) = (void *) 16;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *) 131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *) 132;
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;

struct {
    __u32 type;
    __u32 max_entries;
} lifecycle_events SEC(".maps") = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 1 << 24,
};

struct {
    __u32 type;
    __u32 max_entries;
    __u32 key_size;
    __u32 value_size;
} monitored_cgroups_lifecycle SEC(".maps") = {
    .type = BPF_MAP_TYPE_HASH,
    .max_entries = 10240,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u32),
};

static __always_inline int is_monitored_cgroup(__u64 cgroup_id) {
    void *val = bpf_map_lookup_elem(&monitored_cgroups_lifecycle, &cgroup_id);
    return val != 0;
}

SEC("tracepoint/sched/sched_process_fork")
int on_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (!is_monitored_cgroup(cgroup_id)) {
        return 0;
    }

    struct event *e = bpf_ringbuf_reserve(&lifecycle_events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    e->timestamp = bpf_ktime_get_ns();
    e->cgroup_id = cgroup_id;
    e->pid = ctx->child_pid;
    e->ppid = ctx->parent_pid;
    e->type = EVENT_FORK;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->data[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int on_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (!is_monitored_cgroup(cgroup_id)) {
        return 0;
    }

    struct event *e = bpf_ringbuf_reserve(&lifecycle_events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    e->timestamp = bpf_ktime_get_ns();
    e->cgroup_id = cgroup_id;
    e->pid = ctx->pid;
    e->ppid = ctx->old_pid;
    e->type = EVENT_EXEC;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // Copy filename to data
    for (int i = 0; i < 255 && ctx->filename[i] != '\0'; i++) {
        e->data[i] = ctx->filename[i];
        e->data[i+1] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int on_process_exit(struct trace_event_raw_sched_process_exit *ctx) {
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (!is_monitored_cgroup(cgroup_id)) {
        return 0;
    }

    struct event *e = bpf_ringbuf_reserve(&lifecycle_events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    e->timestamp = bpf_ktime_get_ns();
    e->cgroup_id = cgroup_id;
    e->pid = ctx->pid;
    e->ppid = 0;
    e->type = EVENT_EXIT;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->data[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
