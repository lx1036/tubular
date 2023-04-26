package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"net"
	"net/http"
	"os"
	"os/signal"
)

func main() {
	pid := os.Getpid()
	fmt.Println(fmt.Sprintf("pid is %d", pid))

	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, os.Interrupt)
	for {
		select {
		case <-stopCh:
			logrus.Info("exit bpf program")
			return
		}
	}
}

func main2() {
	fmt.Println("new process")

	engine := gin.Default()
	engine.GET("/hello", func(context *gin.Context) {
		context.String(http.StatusOK, "hello %s,the url path is %s", context.Query("name"), context.Request.URL.Path)
	})
	_ = engine.Run(":9999")
}

func main3() {
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		logrus.Fatal(fmt.Sprintf("failed to create sock fd: %v", err))
	}

	// bind socket to tcp://127.0.0.1:8080
	tcpAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:8010")
	sockAddr := new(unix.SockaddrInet4)
	sockAddr.Port = tcpAddr.Port
	copy(sockAddr.Addr[:], tcpAddr.IP)
	if err = unix.Bind(sock, sockAddr); err != nil {
		logrus.Fatal(fmt.Sprintf("failed to Bind() socket: %v", err))
	}
	if err = unix.Listen(sock, 10); err != nil { // listen() 设置为被动式监听，即设置为服务端
		logrus.Fatal(fmt.Sprintf("failed to Listen() socket: %v", err))
	}

	pid := os.Getpid()
	fmt.Println(fmt.Sprintf("pid is %d", pid))

	// 2. push socket into epoll queue
	epfd, err := unix.EpollCreate(1)
	if err != nil {
		logrus.Fatal(fmt.Sprintf("failed to EpollCreate(): %v", err))
	}
	ev := new(unix.EpollEvent)
	ev.Events = unix.EPOLLIN // 表示对应的文件描述符可以读（包括对端SOCKET正常关闭）
	err = unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, sock, ev)
	if err != nil {
		logrus.Fatal(fmt.Sprintf("failed to EpollCtl(): %v", err))
	}
	events := make([]unix.EpollEvent, 128)
	_, err = unix.EpollWait(epfd, events, 1)
	if err != nil {
		logrus.Fatal(fmt.Sprintf("failed to EpollWait(): %v", err))
	}

	// 3. read bytes from server socket
	go func() {
		for {
			nfd, _, err := unix.Accept(sock)
			bytes := make([]byte, 1000)
			_, err = unix.Read(nfd, bytes)
			if err != nil {
				logrus.Fatal(fmt.Sprintf("failed to Read(): %v", err))
			}
			logrus.Infof(fmt.Sprintf("read bytes from sock: %s", string(bytes)))
		}
	}()

	// 5. client send tcp packet every second
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, os.Interrupt)
	for {
		select {
		case <-stopCh:
			logrus.Info("exit bpf program")
			return
		}
	}
}
