#include "vmlinux.h"
#include "bpf_helpers.h"
#include <bpf_tracing.h>
#include <bpf_core_read.h>

SEC("kprobe/ip_rcv")
int BPF_KPROBE(ip_rcv)
{
	struct iphdr *ip;
	struct sk_buff *skbdata;
	__be32 saddr, daddr;
	
	skbdata = (struct sk_buff*)PT_REGS_PARM1(ctx);
	if (skbdata) {
		unsigned char *head = BPF_CORE_READ(skbdata, head);
		__u16 network_header = BPF_CORE_READ(skbdata, network_header);
		ip = (struct iphdr*)(head + network_header);
		if (ip) {
			saddr = BPF_CORE_READ(ip, saddr);
			daddr = BPF_CORE_READ(ip, daddr);
			bpf_printk("ip_rcv src %x dst %x\n", saddr, daddr); 
		}
	}
	return 0;
}


char LICENSE[] SEC("license") = "GPL";
