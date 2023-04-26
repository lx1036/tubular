

/*
linux-5.10.142/samples/bpf/sockex1_kern.c
linux-5.10.142/samples/bpf/sockex2_kern.c
linux-5.10.142/samples/bpf/sockex3_kern.c
*/


#include <stddef.h>
#include <stdbool.h>

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/errno-base.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>


// #define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
// #define offsetof(TYPE, MEMBER)	((unsigned long)&((TYPE *)0)->MEMBER)
// #define offsetof(TYPE, MEMBER)  __builtin_offsetof(TYPE, MEMBER)


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, long);
	__uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} my_map SEC(".maps");

SEC("socket1")
int bpf_prog1(struct __sk_buff *skb)
{
	int index = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
	long *value;

	if (skb->pkt_type != PACKET_OUTGOING)
		return 0;

	value = bpf_map_lookup_elem(&my_map, &index);
	if (value)
		__sync_fetch_and_add(value, skb->len);

	return 0;
}


struct pair {
	long packets;
	long bytes;
};

struct flow_key_record {
	__be32 src;
	__be32 dst;
	union {
		__be32 ports;
		__be16 port16[2];
	};
	__u16 thoff;
	__u8 ip_proto;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __be32);
	__type(value, struct pair);
	__uint(max_entries, 1024);
} hash_map SEC(".maps");

SEC("socket2")
int bpf_prog2(struct __sk_buff *skb)
{
	struct flow_key_record flow = {};
	struct pair *value;
	__u32 key;

	if (!flow_dissector(skb, &flow))
		return 0;

	key = flow.dst;
	value = bpf_map_lookup_elem(&hash_map, &key);
	if (value) {
		__sync_fetch_and_add(&value->packets, 1);
		__sync_fetch_and_add(&value->bytes, skb->len);
	} else {
		struct pair val = {1, skb->len};

		bpf_map_update_elem(&hash_map, &key, &val, BPF_ANY);
	}
	return 0;
}


char _license[] SEC("license") = "GPL";