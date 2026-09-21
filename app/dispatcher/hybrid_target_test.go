package dispatcher

import (
	"bytes"
	"context"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func newTestHybridTarget() (*hybridTarget, *pipe.Reader, *pipe.Writer) {
	upR, upW := pipe.New(pipe.WithoutSizeLimit())
	downR, downW := pipe.New(pipe.WithoutSizeLimit())
	_, cancel := context.WithCancel(context.Background())
	t := &hybridTarget{link: &transport.Link{Reader: downR, Writer: upW}, cancel: cancel, queue: make(chan *buf.Buffer, 64), done: make(chan struct{})}
	go t.writeLoop()
	return t, upR, downW
}

func TestHybridTargetWritesCopiesInOrder(t *testing.T) {
	target, up, _ := newTestHybridTarget()
	defer target.Close()
	p := make([]byte, 3)
	for i := byte(0); i < 10; i++ {
		p[0], p[1], p[2] = i, i, i
		if err := target.WritePacket(p); err != nil {
			t.Fatal(err)
		}
	}
	big := bytes.Repeat([]byte{9}, buf.Size+100)
	if err := target.WritePacket(big); err != nil {
		t.Fatal(err)
	}
	var got buf.MultiBuffer
	for len(got) < 11 {
		mb, err := up.ReadMultiBuffer()
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, mb...)
	}
	defer buf.ReleaseMulti(got)
	for i, b := range got[:10] {
		if want := []byte{byte(i), byte(i), byte(i)}; !bytes.Equal(b.Bytes(), want) {
			t.Fatalf("datagram %d is %v, want %v", i, b.Bytes(), want)
		}
	}
	if !bytes.Equal(got[10].Bytes(), big) {
		t.Fatalf("oversized datagram came out as %d bytes", got[10].Len())
	}
}

func TestHybridTargetReadsBatchesAndSkipsEmpty(t *testing.T) {
	target, _, down := newTestHybridTarget()
	defer target.Close()
	mb := buf.MultiBuffer{buf.New(), buf.New(), buf.New()}
	mb[0].WriteString("first")
	mb[2].WriteString("third")
	if err := down.WriteMultiBuffer(mb); err != nil {
		t.Fatal(err)
	}
	ps, err := target.ReadPackets()
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 || string(ps[0]) != "first" || string(ps[1]) != "third" {
		t.Fatalf("got %q", ps)
	}

	next := buf.New()
	next.WriteString("fourth")
	if err := down.WriteMultiBuffer(buf.MultiBuffer{next}); err != nil {
		t.Fatal(err)
	}
	if ps, err = target.ReadPackets(); err != nil || len(ps) != 1 || string(ps[0]) != "fourth" {
		t.Fatalf("got %q, %v", ps, err)
	}

	target.Close()
	if _, err := target.ReadPackets(); err == nil {
		t.Fatal("read after close succeeded")
	}
	if err := target.WritePacket([]byte("late")); err == nil {
		t.Fatal("write after close succeeded")
	}
}
