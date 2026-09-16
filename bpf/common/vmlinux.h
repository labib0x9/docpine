#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

typedef __u16 __be16;
typedef __u32 __be32;

struct trace_event_raw_sys_enter {
    unsigned long long unused;
    long int id;
    unsigned long int args[6];
};

struct trace_event_raw_sched_process_fork {
    unsigned long long unused;
    char parent_comm[16];
    int parent_pid;
    char child_comm[16];
    int child_pid;
};

struct trace_event_raw_sched_process_exec {
    unsigned long long unused;
    int pid;
    int old_pid;
    char filename[256];
};

struct trace_event_raw_sched_process_exit {
    unsigned long long unused;
    char comm[16];
    int pid;
    int prio;
};

struct bpf_sock_addr {
    __u32 user_family;
    __u32 user_ip4;
    __u32 user_ip6[4];
    __u32 user_port;
    __u32 family;
    __u32 type;
    __u32 protocol;
    __u32 msg_src_ip4;
    __u32 msg_src_ip6[4];
};

struct file {
    void *f_inode;
};

#endif // __VMLINUX_H__
