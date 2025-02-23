// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// GPTGen: BPF_KPROBE 是一个相对通用的宏，它既可以用于内核空间的 kprobe，也可以用于用户空间的 uprobe。

SEC("uprobe")
// SEC("uprobe//proc/self/exe:uprobe_add")
int BPF_KPROBE(uprobe_add_bpf, int a, int b)
{
	bpf_printk("uprobed_add ENTRY: a = %d, b = %d", a, b);
	return 0;
}

// with a bug
SEC("uretprobe//proc/self/exe:uprobe_add")
int BPF_KRETPROBE(uretprobe_add_bpf, int ret)
{
	bpf_printk("uprobed_add EXIT: return = %d", ret);
	return 0;
}

SEC("uprobe//proc/self/exe:uprobed_sub")
int BPF_KPROBE(uprobe_sub_bpf, int a, int b)
{
	bpf_printk("uprobed_sub ENTRY: a = %d, b = %d", a, b);
	return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(uretprobe_sub_bpf, int ret)
{
	bpf_printk("uprobed_sub EXIT: return = %d", ret);
	return 0;
}
