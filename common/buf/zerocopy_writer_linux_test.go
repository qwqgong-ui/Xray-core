//go:build linux

package buf

import (
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestZeroCopyTCPWriter(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	received := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			received <- err
			return
		}
		defer conn.Close()
		_, err = io.CopyN(io.Discard, conn, 4*Size)
		received <- err
	}()

	conn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	rawConn, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := rawConn.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ZEROCOPY, 1)
	}); err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Skipf("SO_ZEROCOPY is unavailable: %v", err)
	}

	mb := make(MultiBuffer, 4)
	for i := range mb {
		mb[i] = New()
		mb[i].end = Size
		for j := range mb[i].Bytes() {
			mb[i].Bytes()[j] = byte(i + 1)
		}
	}

	// This call is intentionally switched from NewWriter to
	// NewZeroCopyWriter by the implementation under test. Keeping the socket
	// setup identical makes syscall-level A/B traces directly comparable.
	writer := NewZeroCopyWriter(conn)
	if err := writer.WriteMultiBuffer(mb); err != nil {
		t.Fatal(err)
	}
	if err := <-received; err != nil {
		t.Fatal(err)
	}

	zeroCopy, ok := writer.(*zeroCopyWriter)
	if !ok {
		t.Fatal("SO_ZEROCOPY socket did not select zeroCopyWriter")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		zeroCopy.stateMutex.Lock()
		pending := len(zeroCopy.pending)
		zeroCopy.stateMutex.Unlock()
		if pending == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("buffers were not released after zerocopy completion")
}
