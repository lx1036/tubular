


// 内核中的测试代码：
// linux-5.10.142/tools/testing/selftests/bpf/prog_tests/sk_assign.c
// linux-5.10.142/tools/testing/selftests/bpf/progs/test_sk_assign.c


#include <stddef.h>
#include <stdbool.h>

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>


// go 里指针使用 ipv4 *bool
static inline struct bpf_sock_tuple *get_tuple(struct __sk_buff *skb, bool *ipv4, bool *tcp) {
    void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
    struct ethhdr *eth;
    eth = (struct ethhdr *)(data);
	if (eth + 1 > data_end)
		return NULL;

    struct bpf_sock_tuple *result;
    __u8 proto = 0;
    __u64 ihl_len;
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (struct iphdr *)(data+sizeof(*eth));
        if (iph + 1 > data_end) {
            return NULL;
        }
        if (iph->ihl != 5) {
            /* Options are not supported */
			return NULL;
        }

        ihl_len = iph->ihl * 4;
        proto = iph->protocol;
		*ipv4 = true;
        result = (struct bpf_sock_tuple *)&iph->saddr; // 这里为何直接使用 saddr
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)){
    
    } else {
        return (struct bpf_sock_tuple *)data;
    }
    
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return NULL;
    *tcp = (proto == IPPROTO_TCP);
	return result;
}

// Attach a tc direct-action classifier to lo in a fresh network
// namespace, and rewrite all connection attempts to localhost:4321
// to localhost:1234 (for port tests) and connections to unreachable
// IPv4/IPv6 IPs to the local socket (for address tests).

/* Pin map under /sys/fs/bpf/tc/globals/<map name> */
#define PIN_GLOBAL_NS 2

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(__u64));
	__uint(max_entries, 1);
	__uint(pinning, PIN_GLOBAL_NS);
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
} server_map SEC(".maps");

static inline int handle_tcp(struct __sk_buff *skb, struct bpf_sock_tuple *tuple, bool ipv4) {
    struct bpf_sock *sk;
    int ret;
    size_t tuple_len;
    __be16 dport;

    tuple_len = ipv4 ? sizeof(tuple->ipv4) : sizeof(tuple->ipv6);
    if ((void *)tuple + tuple_len > (void *)(long)skb->data_end)
		return TC_ACT_SHOT; // ???
    sk = bpf_skc_lookup_tcp(skb, tuple, tuple_len, BPF_F_CURRENT_NETNS, 0); // 这里应该是找已经建立连接的 socket
	if (sk) {
        if (sk->state != BPF_TCP_LISTEN) // 如果不是 listen socket
			goto assign;
		bpf_sk_release(sk);
    }

    dport = ipv4 ? tuple->ipv4.dport : tuple->ipv6.dport;
	if (dport != bpf_htons(4321)) // redirect :4321 -> :1234
		return TC_ACT_OK;

    const int zero = 0;
    sk = bpf_map_lookup_elem(&server_map, &zero);
	if (!sk)
		return TC_ACT_SHOT; // drop packet
    if (sk->state != BPF_TCP_LISTEN) { // 必须得是 listen socket
		bpf_sk_release(sk);
		return TC_ACT_SHOT;
	}

assign:
	ret = bpf_sk_assign(skb, sk, 0);
	bpf_sk_release(sk);
	return ret;    
}

static inline int handle_udp(struct __sk_buff *skb, struct bpf_sock_tuple *tuple, bool ipv4) {
    struct bpf_sock *sk;
    int ret;
    size_t tuple_len;
    __be16 dport;

    tuple_len = ipv4 ? sizeof(tuple->ipv4) : sizeof(tuple->ipv6);
    if ((void *)tuple + tuple_len > (void *)(long)skb->data_end)
		return TC_ACT_SHOT; // ???
    sk = bpf_sk_lookup_udp(skb, tuple, tuple_len, BPF_F_CURRENT_NETNS, 0);
	if (sk)
		goto assign;

    dport = ipv4 ? tuple->ipv4.dport : tuple->ipv6.dport;
	if (dport != bpf_htons(4321)) // redirect :4321 -> :1234
		return TC_ACT_OK;

    const int zero = 0;
    sk = bpf_map_lookup_elem(&server_map, &zero);
	if (!sk)
		return TC_ACT_SHOT; // drop packet    

assign:
	ret = bpf_sk_assign(skb, sk, 0);
	bpf_sk_release(sk);
	return ret;
}


// 在 tc ingress hook 处
SEC("classifier/sk_assign_test")
int bpf_sk_assign_test(struct __sk_buff *skb)
{
    int ret = 0;
    struct bpf_sock_tuple *tuple;
    bool ipv4 = false;
	bool tcp = false;

    tuple = get_tuple(skb, &ipv4, &tcp);
	if (!tuple)
		return TC_ACT_SHOT; // drop packet

    /* Note that the verifier socket return type for bpf_skc_lookup_tcp()
	 * differs from bpf_sk_lookup_udp(), so even though the C-level type is
	 * the same here, if we try to share the implementations they will
	 * fail to verify because we're crossing pointer types.
	 */
	if (tcp)
		ret = handle_tcp(skb, tuple, ipv4);
	else
		ret = handle_udp(skb, tuple, ipv4);

	return ret == 0 ? TC_ACT_OK : TC_ACT_SHOT;    
}


