#include <stddef.h>
#include <stdbool.h>

#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define BPF_MAP_ID_DIAG_MAP         5



/*value to diag_map*/
struct diag_ip4 {
    bool echo;
    bool verbose;
    bool per_interface;
    bool ssh_disable;
    bool tc_ingress;
    bool tc_egress;
};


//map to keep status of diagnostic rules
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(id, BPF_MAP_ID_DIAG_MAP);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct diag_ip4));
    __uint(max_entries, 28);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} diag_map SEC(".maps");



static inline struct diag_ip4 *get_diag_ip4(__u32 key){
    struct diag_ip4 *if_diag;
    if_diag = bpf_map_lookup_elem(&diag_map, &key);

	return if_diag;
}



SEC("action")
int bpf_sk_splice(struct __sk_buff *skb){

    /*look up attached interface inbound diag status*/
    struct diag_ip4 *local_diag = get_diag_ip4(skb->ingress_ifindex);
    if(!local_diag){
        if(skb->ingress_ifindex == 1){
            return TC_ACT_OK;
        }else{
            return TC_ACT_SHOT; // drop packet
        }
    }




}