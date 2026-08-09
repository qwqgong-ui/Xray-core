package splithttp

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/xtls/xray-core/common/signal/done"
)

func TestFramedDownlinkWritesDataAndHeartbeat(t *testing.T) {
	recorder := httptest.NewRecorder()
	conn := &httpServerConn{
		Instance:       done.New(),
		ResponseWriter: recorder,
		framedDownlink: true,
	}

	payload := []byte("proxy bytes")
	n, err := conn.Write(payload)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) {
		t.Fatalf("Write returned %d, want %d", n, len(payload))
	}
	if err := conn.writeDownlinkHeartbeat(); err != nil {
		t.Fatal(err)
	}

	want := append([]byte{downlinkDataFrame, 0, 0, 0, byte(len(payload))}, payload...)
	want = append(want, downlinkHeartbeatFrame, 0, 0, 0, 0)
	if !bytes.Equal(recorder.Body.Bytes(), want) {
		t.Fatalf("framed body = %x, want %x", recorder.Body.Bytes(), want)
	}
}

func TestUnframedDownlinkRemainsRaw(t *testing.T) {
	recorder := httptest.NewRecorder()
	conn := &httpServerConn{
		Instance:       done.New(),
		ResponseWriter: recorder,
	}
	payload := []byte("raw proxy bytes")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recorder.Body.Bytes(), payload) {
		t.Fatalf("body = %x, want %x", recorder.Body.Bytes(), payload)
	}
}
