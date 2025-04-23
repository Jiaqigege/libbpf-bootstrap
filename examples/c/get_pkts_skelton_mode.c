// SPDX-License-Identifier: BSD-3-Clause
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <net/if.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "get_pkts_skelton_mode.skel.h"

#include <linux/if_link.h>
#include <linux/limits.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <assert.h>
#include <sys/resource.h>

static int ifindex;
static uint32_t xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static struct get_pkts_skelton_mode_bpf *skel;

static void int_exit(int sig)
{
	if (ifindex > 0)
		bpf_xdp_detach(ifindex, xdp_flags, NULL);
	get_pkts_skelton_mode_bpf__destroy(skel);
	exit(0);
}

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "Usage: %s <ifname> <--skb-mode|--drv-mode>\n", argv[0]);
		return 1;
	}

	// 设置rlimit
	struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
	if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		perror("setrlimit");
		return 1;
	}

	// 设置模式
	ifindex = if_nametoindex(argv[1]);
	if (ifindex == 0) {
		perror("if_nametoindex");
		return 1;
	}
	if (strcmp(argv[2], "--skb-mode") == 0)
		xdp_flags |= XDP_FLAGS_SKB_MODE;
	else
		xdp_flags |= XDP_FLAGS_DRV_MODE;

	// 打开skeleton
	skel = get_pkts_skelton_mode_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// 加载程序
	if (get_pkts_skelton_mode_bpf__load(skel)) {
		fprintf(stderr, "Failed to load BPF object\n");
		return 1;
	}

	// 手动附加XDP程序（因为 skeleton 不支持 xdp attach）
	if (bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.xdp_count), xdp_flags, NULL) < 0) {
		perror("bpf_xdp_attach");
		return 1;
	}

	signal(SIGINT, int_exit);

	// 打印 map 中的数据
	while (1) {
		long tcp = 0, udp = 0, icmp = 0;
		int k;

		k = IPPROTO_TCP;
		bpf_map_lookup_elem(bpf_map__fd(skel->maps.stat_map), &k, &tcp);
		k = IPPROTO_UDP;
		bpf_map_lookup_elem(bpf_map__fd(skel->maps.stat_map), &k, &udp);
		k = IPPROTO_ICMP;
		bpf_map_lookup_elem(bpf_map__fd(skel->maps.stat_map), &k, &icmp);

		printf("TCP %ld UDP %ld ICMP %ld packets\n", tcp, udp, icmp);
		sleep(1);
	}
}
