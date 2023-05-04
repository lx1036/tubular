package internal

import (
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cloudflare/tubular/internal/testutil"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"testing"
)

func TestTproxyTcIngress(t *testing.T) {
	netns := testutil.NewNetNS(t)

	spec, err := loadTproxy()

	var specs tproxySpecs
	if err := spec.Assign(&specs); err != nil {
		//return nil, err
	}

	var objs tproxyObjects
	spec.LoadAndAssign(&objs, nil) // load into kernel
	defer objs.Close()

	skAssignProg := objs.BpfSkAssignTest
	link.AttachXDP()

}

// cilium/ebpf 包没有 attach tc，因为 tc bpf_link 内核支持还有问题：https://github.com/cilium/ebpf/discussions/769
// 查看 cilium 源码自己的实现：pkg/datapath/loader/netlink.go
// 和 /Users/liuxiang/lx1036/dropbox-goebpf/program_tc.go 包的实现

// 0xFFFF0000 特殊的 qdisc handle 0xffff:0000 also called clsact, 其 parent 是 netlink.HANDLE_CLSACT.
// clsact 是是一个特殊的 qdisc.
// @see https://lwn.net/Articles/671458/
// ip link add foo type dummy
// ip link set dev foo up
// tc qdisc add dev foo clsact
// tc qdisc show dev foo
// 	qdisc noqueue 0: root refcnt 2
// 	qdisc clsact ffff: parent ffff:fff1
var handle = netlink.MakeHandle(0xffff, 0) // clsact qdisc
func getIngressQdisc(link netlink.Link) (netlink.Qdisc, error) { // 获取绑定在 link 上的 handle 0xffff:0000
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return nil, err
	}

	for _, qdisc := range qdiscs {
		attrs := qdisc.Attrs()
		if attrs.LinkIndex != link.Attrs().Index {
			continue
		}
		if (attrs.Handle&handle) == handle && attrs.Parent == netlink.HANDLE_CLSACT {
			return qdisc, nil
		}
	}

	return nil, nil
}
func replaceQdisc(link netlink.Link) error {
	ingressQdisc, err := getIngressQdisc(link)

	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    handle,
		Parent:    netlink.HANDLE_CLSACT,
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	return netlink.QdiscReplace(qdisc)
}
func AttachTc() {

	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("getting interface %s by name: %w", ifName, err)
	}

	if err := replaceQdisc(link); err != nil {
		return fmt.Errorf("replacing clsact qdisc for interface %s: %w", link.Attrs().Name, err)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    qdiscParent,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
			Priority:  option.Config.TCFilterPriority,
		},
		Fd:           prog.FD(),
		Name:         fmt.Sprintf("cilium-%s", link.Attrs().Name),
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("replacing tc filter: %w", err)
	}

}
