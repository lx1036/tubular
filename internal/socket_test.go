package internal

import (
	"bytes"
	"fmt"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"testing"
	"time"
)

// /Users/liuxiang/go/pkg/mod/golang.org/x/sys@v0.5.0/unix/syscall_unix_test.go

// go test -v -run ^TestSend$ .
func TestSend(t *testing.T) {
	ec := make(chan error, 2)
	ts := []byte("abc")

	fds, err := unix.Socketpair(unix.AF_LOCAL, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	go func() {
		data := make([]byte, len(ts))
		// 阻塞的, server
		_, _, err := unix.Recvfrom(fds[1], data, 0)
		if err != nil {
			ec <- err
		}

		logrus.Infof(fmt.Sprintf("%s", string(data)))
		if !bytes.Equal(ts, data) {
			ec <- fmt.Errorf("data sent != data received. Received %q", data)
		}
		ec <- nil
	}()

	err = unix.Send(fds[0], ts, 0)
	if err != nil {
		ec <- err
	}

	select {
	case err = <-ec:
		if err != nil {
			t.Fatalf("Send: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Send: nothing received after 2 seconds")
	}
}
