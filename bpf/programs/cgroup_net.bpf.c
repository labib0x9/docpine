//go:build ignore
#include "../common/vmlinux.h"
#include "../common/types.h"

#define BPF_MAP_TYPE_HASH 1
#define SEC(NAME) __attribute__((section(NAME), used))

static __u64 (*bpf_get_current_cgroup_id)(void) = (void *) 80;
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;

// Network firewall rules map: (cgroup_id, dst_ip, dst_port) -> action (1=allow, 0=deny)
struct {
    __u32 type;
    __u32 max_entries;
    __u32 key_size;
    __u32 value_size;
} net_policy_map SEC(".maps") = {
    .type = BPF_MAP_TYPE_HASH,
    .max_entries = 65536,
    .key_size = sizeof(struct net_policy_key),
    .value_size = sizeof(struct net_policy_val),
};

SEC("cgroup/connect4")
int net_connect4(struct bpf_sock_addr *ctx) {
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    struct net_policy_key key = {
        .cgroup_id = cgroup_id,
        .dst_ip = ctx->user_ip4,
        .dst_port = (__u16)ctx->user_port,
        ._pad = 0,
    };

    struct net_policy_val *rule = bpf_map_lookup_elem(&net_policy_map, &key);
    if (rule) {
        if (rule->action == 0) {
            return 0; // Reject outbound connection in-kernel
        }
    }

    return 1; // Allow
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
