// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe")
int BPF_KPROBE(uprobe_damon_custom_bpf, int a, int b)
{
	bpf_printk("damon_custom ENTRY: a = %d, b = %d", a, b);
	return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(uretprobe_damon_custom_bpf, int ret)
{
	bpf_printk("damon_custom EXIT: return = %d", ret);
	return 0;
}
