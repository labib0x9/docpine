//go:build ignore
#include "../common/vmlinux.h"
#include "../common/types.h"

#define BPF_MAP_TYPE_HASH 1
#define SEC(NAME) __attribute__((section(NAME), used))
#define EPERM 1

static __u64 (*bpf_get_current_cgroup_id)(void) = (void *) 80;
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;

// Blocklist map for sensitive file access enforcement
struct {
    __u32 type;
    __u32 max_entries;
    __u32 key_size;
    __u32 value_size;
} fs_deny_policy_map SEC(".maps") = {
    .type = BPF_MAP_TYPE_HASH,
    .max_entries = 10240,
    .key_size = sizeof(struct fs_policy_key),
    .value_size = sizeof(__u32),
};

SEC("lsm/file_open")
int BPF_PROG(block_file_open, struct file *file) {
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    
    // In-kernel LSM check against policy map
    struct fs_policy_key key = {
        .cgroup_id = cgroup_id,
        .inode = 0,
        .dev = 0,
    };

    void *denied = bpf_map_lookup_elem(&fs_deny_policy_map, &key);
    if (denied) {
        return -EPERM; // Denied by kernel LSM
    }

    return 0; // Allowed
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
