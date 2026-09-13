#ifndef __DOCPINE_TYPES_H__
#define __DOCPINE_TYPES_H__

// EventType enumerates system activity observed in the kernel
enum event_type {
    EVENT_EXEC = 0,
    EVENT_OPENAT = 1,
    EVENT_CONNECT = 2,
    EVENT_SETNS = 3,
    EVENT_UNSHARE = 4,
    EVENT_CAPABILITY_CHANGE = 5,
    EVENT_NAMESPACE_CHANGE = 6,
    EVENT_FORK = 7,
    EVENT_EXIT = 8,
    EVENT_PTRACE = 9,
    EVENT_MOUNT = 10,
    EVENT_BPF = 11,
};

// struct event is the unified binary event emitted across the RINGBUF map to Go
struct event {
    unsigned long long timestamp; // nanoseconds monotonic
    unsigned long long cgroup_id; // bpf_get_current_cgroup_id()
    unsigned int pid;            // tgid (process ID in root namespace)
    unsigned int ppid;           // parent process ID
    unsigned int type;           // enum event_type
    char comm[16];               // executable name
    char data[256];              // serialized event payload (file path, ip:port, etc.)
};

// struct net_policy_key defines the in-kernel firewall lookup key
struct net_policy_key {
    unsigned long long cgroup_id;
    unsigned int dst_ip;         // IPv4 network-byte-order
    unsigned short dst_port;     // Port network-byte-order
    unsigned short _pad;
};

// struct net_policy_val defines allow/deny verdict for cgroup/connect
struct net_policy_val {
    unsigned int action;         // 0 = deny, 1 = allow
};

// struct cap_policy_val defines bitmask of allowed capabilities
struct cap_policy_val {
    unsigned long long allowed_caps;
};

// struct fs_policy_key defines sensitive file path/inode allowlist
struct fs_policy_key {
    unsigned long long cgroup_id;
    unsigned long long inode;
    unsigned int dev;
};

#endif // __DOCPINE_TYPES_H__
