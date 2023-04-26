package internal

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cloudflare/tubular/internal/testutil"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"math/rand"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

const (
	IO_TIMEOUT_SEC = 3

	SOMAXCONN = 4096
)

func init() {
	testutil.EnterUnprivilegedMode()
	rand.Seed(time.Now().UnixNano())
}

const (
	SOCK_STREAM = iota + 1
	SOCK_DGRAM
	SOCK_RAW
)

const (
	Server_A = iota
	Server_B
	MaxServers
)

func make_client(socketType int) int {
	sockFd, err := make_socket(socketType)
	unix.Connect(sockFd, addr)

	return sockFd
}

func make_server(socketType int, reuseportProg *ebpf.Program) int {
	sockFd, err := make_socket(socketType)
	if err != nil {
		logrus.Fatal(err)
		return 0
	}

	switch socketType {
	case SOCK_STREAM:
		err = unix.SetsockoptInt(sockFd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		if err != nil {
			return 0, err
		}
	case SOCK_DGRAM:
		err = unix.SetsockoptInt(sockFd, unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
		if err != nil {
			return 0, err
		}

	}

	if reuseportProg != nil {
		err = unix.SetsockoptInt(sockFd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		if err != nil {
			return 0, err
		}
	}

	err = unix.Bind(sockFd, &unix.SockaddrInet4{
		Port: 8081,
		Addr: [4]byte{127, 0, 0, 1},
	})

	if socketType == SOCK_STREAM {
		err = unix.Listen(sockFd, SOMAXCONN)
	}

	if reuseportProg != nil {
		// attach sk_reuseport prog, 为了证明 sk_lookup 不影响 sk_reuseport prog
		err = unix.SetsockoptInt(sockFd, unix.SOL_SOCKET, unix.SO_ATTACH_REUSEPORT_EBPF, p.GetFd())
	}

	return sockFd
}

func make_socket(socketType int) (int, error) {
	var (
		fd  int
		err error
	)

	switch socketType {
	case SOCK_STREAM:
		fd, err = unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
		if err != nil {
			return 0, err
		}

	case SOCK_DGRAM:
		fd, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
		if err != nil {
			return 0, err
		}

	default:
		err = fmt.Errorf("unknown socket type")
	}
	if err != nil {
		return 0, err
	}

	// send/receive timeout 3s
	err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &unix.Timeval{
		Sec: IO_TIMEOUT_SEC,
	})
	if err != nil {
		return 0, err
	}
	err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{
		Sec: IO_TIMEOUT_SEC,
	})
	if err != nil {
		return 0, err
	}

	return fd, nil
}

func isIPv4(ip string) bool {
	i := net.ParseIP(ip)
	return i.To4() != nil
}

func isIPv6(ip string) bool {
	i := net.ParseIP(ip)
	return i.To16() != nil
}

func attachLookupProg(netns ns.NetNS, prog *ebpf.Program) {

	if err := prog.Pin(programPath(tempDir)); err != nil { // pin sk_lookup program: /sys/fs/bpf/4026531840_dispatcher/program
		return nil, fmt.Errorf("pin program: %s", err)
	}

	// The dispatcher is active after this call.
	link, err := link.AttachNetNs(int(netns.Fd()), prog) // attach sk_lookup program to tmped netns
	if err != nil {
		return nil, fmt.Errorf("attach program to netns %s: %s", netns.Path(), err)
	}
	defer link.Close()

	if err := link.Pin(linkPath(tempDir)); err != nil {
		return nil, fmt.Errorf("can't pin link: %s", err)
	}

	if err := adjustPermissions(tempDir); err != nil {
		return nil, fmt.Errorf("adjust permissions: %s", err)
	}

	// Rename will succeed if pinPath doesn't exist or is an empty directory,
	// otherwise it will return an error. In that case tempDir is removed,
	// and the pinned link + program are closed, undoing any changes.
	if err := os.Rename(tempDir, pinPath); os.IsExist(err) || errors.Is(err, syscall.ENOTEMPTY) {
		return nil, fmt.Errorf("can't create dispatcher: %w", ErrLoaded)
	} else if err != nil {
		return nil, fmt.Errorf("can't create dispatcher: %s", err)
	}

}

var data1 = []byte("abc")
var data2 = []byte("bcd")

func tcp_echo_test(clientFd, serverFd int) {
	sendByte(clientFd)
	tcpRecvSend(serverFd)
	recvByte(clientFd)
}

func udp_echo_test(clientFd, serverFd int) {
	sendByte(clientFd)
	udpRecvSend(serverFd)
	recvByte(clientFd)
}

// client 发送数据
func sendByte(clientFd int) {
	// send() may be used only when the socket is in a connected state,
	// while sendto() and sendmsg() may be used at any time.
	// If no messages space is available at the socket to hold the message to be
	//     transmitted, then send() normally blocks, unless the socket has been
	//     placed in non-blocking I/O mode.  The select(2) call may be used to
	//     determine when it is possible to send more data.
	err := unix.Send(clientFd, data1, 0) // clientFd send "abc" -> serverFd
}

func recvByte(clientFd int) {
	buf := make([]byte, len(data2))
	_, _, err := unix.Recvfrom(clientFd, buf, 0) // server receive buf from client
}

func tcpRecvSend(serverFd int) {
	nfd, _, err := unix.Accept(serverFd) // 这里是新的 fd
	buf := make([]byte, len(data1))
	_, _, err = unix.Recvfrom(nfd, buf, 0) // read from fd
	err = unix.Send(nfd, data2, 0)         // write into fd

	err = unix.Close(nfd) // 每次都要新建和关闭 nfd
}

func udpRecvSend(serverFd int) {
	cbuf := make([]byte, unix.CmsgSpace(4))
	_, cn, _, sockAddr, err := unix.Recvmsg(serverFd, nil, cbuf, 0)

	/* Reply from original destination address. */
	nfd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	socketAddr, err := unix.Getsockname(serverFd)
	err = unix.Bind(nfd, socketAddr)

	err = unix.Send(nfd, data2, 0)
	err = unix.Close(nfd) // 每次都要新建和关闭 nfd
}

func TestBPFLoad(t *testing.T) {
	netns := testutil.NewNetNS(t)

	skel, err := GetSkel(netns.Path(), "/sys/fs/bpf")

	fixtures := []struct {
		desc              string
		lookupProg        *ebpf.Program
		reuseportProg     *ebpf.Program
		socketMap         *ebpf.Map
		socketType        int
		reuseportHasConns bool
		acceptOn          int
	}{
		{
			desc:       "TCP IPv4 redir port",
			lookupProg: skel.Objs.RedirPort,
			socketMap:  skel.Objs.RedirMap,
			socketType: SOCK_STREAM,
		},
	}

	for _, fixture := range fixtures {

		// 1.create some servers and update redir_map
		server_fds := [MaxServers]int{}
		attachLookupProg(netns, fixture.lookupProg)
		for i := 0; i < MaxServers; i++ {
			server_fds[i] = make_server(fixture.socketType, fixture.reuseportProg)
			err = fixture.socketMap.Put(i, server_fds[i])
			/* want just one server for non-reuseport test */
			if fixture.reuseportProg == nil {
				break
			}
		}

		/* Regular UDP socket lookup with reuseport behaves
		 * differently when reuseport group contains connected
		 * sockets. Check that adding a connected UDP socket to the
		 * reuseport group does not affect how reuseport works with
		 * BPF socket lookup.
		 */
		reuseConnFd := -1
		if fixture.reuseportHasConns {
			reuseConnFd = make_server(fixture.socketType, fixture.reuseportProg)
			/* Add an extra socket to reuseport group */
			sockAddr, err := unix.Getsockname(reuseConnFd)
			/* Connect the extra socket to itself */
			err = unix.Connect(reuseConnFd, sockAddr)
		}

		// create a client
		clientFd := make_client(fixture.socketType)

		// tcp/udp echo test
		switch fixture.socketType {
		case SOCK_STREAM:
			tcp_echo_test(clientFd, server_fds[fixture.acceptOn])
		case SOCK_DGRAM:
			udp_echo_test(clientFd, server_fds[fixture.acceptOn])
		default:
		}

		unix.Close(clientFd)
		if reuseConnFd != -1 {
			unix.Close(reuseConnFd)
		}

		for i := 0; i < len(server_fds); i++ {
			if server_fds[i] != 0 {
				unix.Close(server_fds[i])
			}
		}
	}

}
