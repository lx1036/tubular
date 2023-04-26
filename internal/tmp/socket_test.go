package tmp

import (
	"fmt"
	"net"
	"testing"
)

func TestAddr(t *testing.T) {
	byte("a")
	addr := net.IP{}
	addr2 := [4]byte{127, 0, 0, 1}
	fmt.Printf(fmt.Sprintf("%+v", addr2))
}
