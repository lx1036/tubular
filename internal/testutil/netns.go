package testutil

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

// CurrentNetNS returns the current thread's network namespace.
func CurrentNetNS(tb testing.TB) ns.NetNS {
	tb.Helper()
	netns, err := ns.GetCurrentNS()
	if err != nil {
		tb.Fatal(err)
	}
	return netns
}

// NewNetNS creates a pristine network namespace.
func NewNetNS(tb testing.TB, networks ...string) ns.NetNS {
	tb.Helper()

	quit := make(chan struct{})
	result := make(chan ns.NetNS, 1)
	errs := make(chan error, 1)

	go func() {
		errs <- WithCapabilities(func() error {
			return setupNetNS(networks, result, quit)
		}, cap.SYS_ADMIN)
	}()

	select {
	case err := <-errs:
		tb.Fatal(err)
		return nil

	case netns := <-result:
		tb.Cleanup(func() {
			close(quit)
			netns.Close()
		})

		return netns
	}
}

func SetupLoopback() error {
	ip := exec.Command("/sbin/ip", "link", "set", "dev", "lo", "up")
	ip.SysProcAttr = &syscall.SysProcAttr{
		AmbientCaps: []uintptr{
			uintptr(cap.NET_ADMIN),
		},
	}
	if out, err := ip.CombinedOutput(); err != nil {
		if len(out) > 0 {
			fmt.Println(string(out))
		}
		return err
	}
	return nil
}

func setupNetNS(networks []string, result chan<- ns.NetNS, quit <-chan struct{}) error {
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil { // 新建 netns `ip netns add netns1`
		return fmt.Errorf("unshare: %s", err)
	}

	if err := ChangeEffectiveCaps(); err != nil {
		return err
	}

	for _, file := range []string{
		"/proc/sys/net/ipv4/ip_nonlocal_bind",
		"/proc/sys/net/ipv6/ip_nonlocal_bind",
	} {
		if err := os.WriteFile(file, []byte("1\n"), 0666); err != nil {
			return fmt.Errorf("enable nonlocal bind: %s", err)
		}
	}

	caps := &syscall.SysProcAttr{
		AmbientCaps: []uintptr{
			uintptr(cap.NET_ADMIN),
		},
	}

	if err := SetupLoopback(); err != nil {
		return fmt.Errorf("set up loopback: %s", err)
	}

	for _, network := range networks {
		ip := exec.Command("/sbin/ip", "route", "add", "local", network, "dev", "lo")
		ip.SysProcAttr = caps
		if out, err := ip.CombinedOutput(); err != nil {
			if len(out) > 0 {
				fmt.Println(string(out))
			}
			return fmt.Errorf("add routes: %s", err)
		}
	}

	for _, network := range networks {
		ip := exec.Command("/sbin/ip", "addr", "add", "dev", "lo", network, "nodad", "noprefixroute")
		ip.SysProcAttr = caps
		if out, err := ip.CombinedOutput(); err != nil {
			if len(out) > 0 {
				fmt.Println(string(out))
			}
			return fmt.Errorf("add networks: %s", err)
		}
	}

	netns, err := ns.GetCurrentNS()
	if err != nil {
		return fmt.Errorf("get current network namespace: %s", err)
	}

	result <- netns

	// Block the goroutine (and the thread) until the
	// network namespace isn't needed anymore.
	<-quit
	return nil
}

// JoinNetNS executes a function in a different network namespace.
//
// Any goroutines invoked from the function will still execute in the
// parent network namespace.
func JoinNetNS(tb testing.TB, netns ns.NetNS, fn func() error, caps ...cap.Value) {
	tb.Helper()

	err := WithCapabilities(func() error {
		if err := netns.Set(); err != nil {
			return fmt.Errorf("set netns: %s", err)
		}

		if err := ChangeEffectiveCaps(caps...); err != nil {
			return err
		}

		return fn()
	}, cap.SYS_ADMIN)
	if err != nil {
		tb.Fatal(err)
	}
}

// ListenAndEcho calls Listen and then starts an echo server on the returned connection.
func ListenAndEcho(tb testing.TB, netns ns.NetNS, network, address string) (sys syscall.Conn) {
	return ListenAndEchoWithName(tb, netns, network, address, "default")
}

const maxNameLen = 128

// Listen listens on a given address in a specific network namespace.
//
// Uses a local address if address is empty.
func Listen(tb testing.TB, netns ns.NetNS, network, address string) (sys syscall.Conn) {
	if address == "" {
		switch network {
		case "tcp", "tcp4", "udp", "udp4":
			address = "127.0.0.1:0"
		case "tcp6", "udp6":
			address = "[::1]:0"
		case "unix", "unixpacket", "unixgram":
			address = filepath.Join(tb.TempDir(), "sock")
		default:
			tb.Fatal("Don't know how to make address for", network)
		}
	}
	JoinNetNS(tb, netns, func() error {
		switch network {
		case "tcp", "tcp4", "tcp6", "unix", "unixpacket":
			ln, err := net.Listen(network, address)
			if err != nil {
				return err
			}
			sys = ln.(syscall.Conn)

			tb.Cleanup(func() {
				ln.Close()
			})

		case "udp", "udp4", "udp6", "unixgram":
			conn, err := net.ListenPacket(network, address)
			if err != nil {
				return err
			}
			sys = conn.(syscall.Conn)

			tb.Cleanup(func() {
				conn.Close()
			})

		default:
			return fmt.Errorf("unsupported network: %s", network)
		}

		return nil
	})

	return
}

// ListenAndEchoWithName is like ListenAndEcho, except that you can distinguish
// multiple listeners by using CanDialName.
func ListenAndEchoWithName(tb testing.TB, netns ns.NetNS, network, address, name string) (sys syscall.Conn) {
	if len(name) > maxNameLen {
		tb.Fatalf("name exceeds %d bytes", maxNameLen)
	}

	sys = Listen(tb, netns, network, address)
	go echo(tb, network, sys, name)
	return
}

func echo(tb testing.TB, network string, sys syscall.Conn, name string) {
	switch network {
	case "tcp", "tcp4", "tcp6", "unix", "unixpacket":
		ln := sys.(net.Listener)
		for {
			conn, err := ln.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					tb.Error("Can't accept:", err)
				}
				return
			}

			go func() {
				defer conn.Close()

				conn.SetWriteDeadline(time.Now().Add(time.Second))
				_, err := conn.Write([]byte(name))
				if err != nil {
					tb.Error(err)
					return
				}

				_, err = io.Copy(ioutil.Discard, conn)
				if err != nil {
					tb.Error(err)
				}
			}()
		}

	case "udp", "udp4", "udp6", "unixgram":
		conn := sys.(net.PacketConn)
		for {
			var buf [1]byte
			_, from, err := conn.ReadFrom(buf[:])
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					tb.Error("Can't read UDP packets:", err)
				}
				return
			}

			conn.WriteTo([]byte(name), from)
		}

	default:
		tb.Fatal("Unsupported network:", network)
	}
}

// CanDial returns true if an address can be dialled in a specific network namespace.
func CanDial(tb testing.TB, netns ns.NetNS, network, address string) (ok bool) {
	tb.Helper()

	JoinNetNS(tb, netns, func() error {
		tb.Helper()

		_, conn := dial(tb, network, address)
		if conn != nil {
			ok = true
			conn.(io.Closer).Close()
		}

		return nil
	})

	return
}

// CanDialName checks that a ListenWithName is reachable at the given network and address.
func CanDialName(tb testing.TB, netns ns.NetNS, network, address, name string) {
	tb.Helper()

	var (
		conn     syscall.Conn
		haveName string
	)
	JoinNetNS(tb, netns, func() error {
		haveName, conn = dial(tb, network, address)
		return nil
	})
	if conn == nil {
		tb.Fatal("Can't dial", network, address)
	}
	conn.(io.Closer).Close()

	if haveName != name {
		tb.Fatalf("Expected to reach %q at %s %s, got %q instead", name, network, address, haveName)
	}
}

// Dial connects to network and address in the given network namespace.
func Dial(tb testing.TB, netns ns.NetNS, network, address string) (conn syscall.Conn) {
	tb.Helper()

	JoinNetNS(tb, netns, func() error {
		_, conn = dial(tb, network, address)
		return nil
	})
	if conn == nil {
		tb.Fatal("Can't dial:", network, address)
	}

	return
}

func dial(tb testing.TB, network, address string) (string, syscall.Conn) {
	tb.Helper()

	dialer := net.Dialer{
		Timeout: 100 * time.Millisecond,
	}

	switch network {
	case "tcp", "tcp4", "tcp6":
		conn, err := dialer.Dial(network, address)
		if errors.Is(err, unix.ECONNREFUSED) {
			return "", nil
		}
		if err != nil {
			tb.Fatal("Can't dial:", err)
		}
		tb.Cleanup(func() { conn.Close() })

		buf := make([]byte, maxNameLen)
		n, err := conn.Read(buf)
		if err != nil {
			conn.Close()
			tb.Fatal("Can't read name:", err)
		}

		return string(buf[:n]), conn.(syscall.Conn)

	case "udp", "udp4", "udp6":
		conn, err := dialer.Dial(network, address)
		if err != nil {
			tb.Fatal("Can't dial:", err)
		}
		tb.Cleanup(func() { conn.Close() })

		message := []byte("a")
		_, err = conn.Write(message)
		if err != nil {
			tb.Fatal("Can't write:", err)
		}

		conn.SetReadDeadline(time.Now().Add(time.Second))

		buf := make([]byte, maxNameLen)
		n, err := conn.Read(buf)
		if errors.Is(err, unix.ECONNREFUSED) {
			conn.Close()
			return "", nil
		}
		if err != nil {
			tb.Fatal("Can't read:", err)
		}

		return string(buf[:n]), conn.(syscall.Conn)

	default:
		panic("unsupported network: " + network)
	}
}
