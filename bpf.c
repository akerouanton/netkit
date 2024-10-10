//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/if_link.h>

char LICENSE[] SEC("license") = "GPL";

#define L3_OFF          ETH_HLEN                          // = 14 bytes
#define IPv4_OFF        (L3_OFF + sizeof(struct iphdr))   // = 14 bytes + 20 bytes = 34 bytes

#define OTHER_END 0x01001eac  // 172.30.0.1 in network byte order
#define NET_PREFIX 0x1eac     // Subnet prefix 172.30/16 in network byte order
#define NET_MASK   0xffff     // Subnet mask 255.255.0.0

#define AF_INET		2	/* Internet IP Protocol 	*/

volatile const __u32 fib_iif = 0;

// NETKIT_DROP == TCX_DROP // NETKIT_REDIRECT == TCX_REDIRECT
static int fib_redirect(struct __sk_buff *skb, __be32 daddr) {
    // See:
    //  - https://elixir.bootlin.com/linux/v6.11.2/source/include/uapi/linux/bpf.h#L7158
    //  - https://github.com/torvalds/linux/blob/75b607fab38d149f232f01eae5e6392b394dd659/net/core/filter.c#L5892
    struct bpf_fib_lookup fib_params = {
        .family = AF_INET,
        .ifindex = fib_iif,
        .ipv4_dst = daddr,
    };

    int fib_res = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params), 0);
    if (fib_res == BPF_FIB_LKUP_RET_FWD_DISABLED || fib_res == BPF_FIB_LKUP_RET_NOT_FWDED) {
        return NETKIT_PASS;
    }
    if (fib_res != 0 && fib_res != BPF_FIB_LKUP_RET_NO_NEIGH) {
        // bpf_printk("failed to look up route for daddr %08x (res: %d)", daddr, fib_res);
        return NETKIT_DROP;
    }

    if (fib_params.ifindex == skb->ingress_ifindex) {
        // bpf_printk("fib_params.ifindex == skb->ingress_ifindex (%d)", fib_params.ifindex);
        return NETKIT_PASS;
    }

    // bpf_printk("successful FIB lookup! ifindex: %d", fib_params.ifindex);
    bpf_redirect(fib_params.ifindex, 0);

    // If fib_res == BPF_FIB_LKUP_RET_NO_NEIGH, smac and dmac are all-zeroes.
    // We need to reinitialize the MAC addresses in the Ethernet header in this
    // case, otherwise nk1 will drop the packet. So, even if there's no neigh,
    // write all-zeroes MAC addresses.
    if (bpf_skb_store_bytes(skb, 0, &fib_params.dmac, ETH_ALEN, 0) != 0) {
        bpf_printk("failed to store dest MAC address");
        return NETKIT_DROP;
    }

    if (bpf_skb_store_bytes(skb, ETH_ALEN, &fib_params.smac, ETH_ALEN, 0) != 0) {
        bpf_printk("failed to store source MAC address");
        return NETKIT_DROP;
    }

    return NETKIT_REDIRECT;
}

SEC("netkit/peer")
int egress_redirect(struct __sk_buff *skb) {
    void *data = (void *)(long) skb->data;
    void *data_end = (void *)(long) skb->data_end;

    if (data_end < (data + IPv4_OFF)) {
        return NETKIT_PASS;
    }

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return NETKIT_PASS;
    }

    struct iphdr *ipv4 = data + L3_OFF;
    if (ipv4->daddr == OTHER_END) {
        return NETKIT_PASS; // Packet going to the other end of the netkit pair
    }

    return fib_redirect(skb, ipv4->daddr);
}

SEC("tcx/ingress")
int host_ingress(struct __sk_buff *skb) {
    void *data = (void *)(long) skb->data;
    void *data_end = (void *)(long) skb->data_end;

    if (data_end < (data + IPv4_OFF)) {
        return TCX_PASS;
    }

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TCX_PASS;
    }

    struct iphdr *ipv4 = data + L3_OFF;
    if ((ipv4->daddr & NET_MASK) != NET_PREFIX) {
        // This packet isn't addressed to the netkit subnet, don't try to
        // fastpath it.
        return TCX_PASS;
    }

    return fib_redirect(skb, ipv4->daddr);
}
