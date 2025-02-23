// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bootstrap_igsys.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct tsk_info {
    u64 start_ts;
    char filename[MAX_FILENAME_LEN];
    bool is_sys_binary;
};

// SEC将exec_start rb都映射到BPF的.map段内
struct {
    __uint(type, BPF_MAP_TYPE_HASH); // BPF_MAP_TYPE_HASH，即一个哈希表
    __uint(max_entries, 8192); // 最多可以存储 8192 个键值对
    __type(key, pid_t);
    __type(value, struct tsk_info);
} exec_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF); // BPF_MAP_TYPE_RINGBUF，环形缓冲区（Ring Buffer）
    __uint(max_entries, 256 * 1024); // 最大条目数为 256 * 1024
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;

static void *bpf_memmem(const void *haystack, size_t haystack_len,
                        const void *needle, size_t needle_len)
{
    const char *h = haystack;
    const char *n = needle;
    size_t i, j;

    // Perform early exit if the needle is too large to fit
    if (needle_len > haystack_len) return NULL;

    for (i = 0; i <= haystack_len - needle_len; i++) {
        for (j = 0; j < needle_len; j++) {
            if (h[i + j] != n[j]) {
                break;
            }
        }
        if (j == needle_len) {
            return (void *)(h + i);
        }
    }
    return NULL;
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    pid_t pid;
    u64 ts;
    struct tsk_info tif = {0}; // Ensure it's zero-initialized

    // get filename
    unsigned fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&tif.filename, sizeof(tif.filename), (void *)ctx + fname_off);
    
    // 检查 filename 是否包含 "/usr/bin" 或 "/usr/sbin"
    if (bpf_memmem(tif.filename, sizeof(tif.filename), "/usr/bin", 8) || 
        bpf_memmem(tif.filename, sizeof(tif.filename), "/usr/sbin", 9)) {
        tif.is_sys_binary = true;
    } else {
        tif.is_sys_binary = false;
    }

    tif.start_ts = bpf_ktime_get_ns();

    /* Remember time exec() was executed for this PID */
    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&exec_start, &pid, &tif, BPF_ANY);

    // Early exit for system binaries
    if (tif.is_sys_binary)
        return 0;

    // Don't emit exec events when minimum duration is specified
    if (min_duration_ns)
        return 0;

    // Reserve sample from BPF ringbuf
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    // Fill out the sample with data
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->exit_event = false;
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->filename, tif.filename, sizeof(e->filename));

    // Successfully submit it to user-space for post-processing
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    pid_t pid, tid;
    u64 id, duration_ns = 0;
    struct tsk_info *tif;
    bool is_sys_binary = false;
    char filename[MAX_FILENAME_LEN] = {0};

    // Get PID and TID of exiting thread/process
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (u32)id;

    // Ignore thread exits
    if (pid != tid)
        return 0;

    // If we recorded start of the process, calculate lifetime duration
    tif = bpf_map_lookup_elem(&exec_start, &pid);
    if (tif) {
        duration_ns = bpf_ktime_get_ns() - tif->start_ts;
        __builtin_memcpy(filename, tif->filename, sizeof(filename));
        is_sys_binary = tif->is_sys_binary;
        bpf_map_delete_elem(&exec_start, &pid);    
    } else if (min_duration_ns) {
        return 0;
    }

    // Early exit for system binaries or if the process ran too short
    if (is_sys_binary || (min_duration_ns && duration_ns < min_duration_ns))
        return 0;

    // Reserve sample from BPF ringbuf
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    // Fill out the sample with data
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->exit_event = true;
    e->duration_ns = duration_ns;
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
	if (filename[0] != 0)
    	__builtin_memcpy(e->filename, filename, sizeof(e->filename));
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Send data to user-space for post-processing
    bpf_ringbuf_submit(e, 0);
    return 0;
}
