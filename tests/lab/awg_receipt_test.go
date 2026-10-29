// Reproduction-only lab, not a finalization adapter.
// Copy into device/ of amnezia-vpn/amneziawg-go at
// b5928efb6ca19f0153958460c3d141f04abc5c2e, then run:
// go test ./device -run '^TestReceipt' -count=3 -timeout=90s -v
// Uses real loopback UDP, encrypted AWG packets, and in-memory ChannelTUN.
// S4 is deliberately left at its default: the upstream nonzero-S4 ping
// test fails on this revision in the Windows lab. No kernel backend proof.
package device

// Isolated protocol experiment: real AWG UDP sockets and encrypted IP packets,
// ChannelTUN instead of a privileged OS interface. No production configuration.
import (
	"encoding/hex"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func receiptPair(t *testing.T) testPair {
	return genTestPair(t, true, "jc", "3", "jmin", "10", "jmax", "30",
		"s1", "15", "s2", "18", "s3", "20",
		"h1", "123456-123500", "h2", "67543-67550",
		"h3", "123123-123200")
}

func receiptPeer(t *testing.T, d *Device) (*Peer, string) {
	t.Helper()
	d.peers.RLock()
	defer d.peers.RUnlock()
	for key, p := range d.peers.keyMap {
		return p, hex.EncodeToString(key[:])
	}
	t.Fatal("expected one synthetic peer")
	return nil, ""
}

func receiptAwait(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatal("bounded protocol wait timed out")
		}
		runtime.Gosched()
	}
}

func TestReceiptReadRemoveGap(t *testing.T) {
	pair := receiptPair(t)
	pair.Send(t, Ping, nil)
	peer, key := receiptPeer(t, pair[0].dev)
	snapshot, err := pair[0].dev.IpcGet()
	if err != nil || !strings.Contains(snapshot, "rx_bytes=") {
		t.Fatal("UAPI read failed")
	}
	scraped := peer.rxBytes.Load()
	// A deterministic gap after scrape, followed by traffic concurrent with
	// removal. Capture the retired pointer only in this instrumented lab;
	// normal UAPI callers cannot obtain it after remove=true.
	pair.Send(t, Ping, nil)
	receiptAwait(t, func() bool { return peer.rxBytes.Load() > scraped })
	var delivered atomic.Uint64
	stop := make(chan struct{})
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for {
			select {
			case <-pair[0].tun.Inbound:
				delivered.Add(1)
			case <-stop:
				return
			}
		}
	}()
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		for i := 0; i < 100; i++ {
			select {
			case pair[1].tun.Outbound <- tuntest.Ping(pair[0].ip, pair[1].ip):
			case <-stop:
				return
			}
		}
	}()
	receiptAwait(t, func() bool { return delivered.Load() >= 10 })
	if err := pair[0].dev.IpcSet(uapiCfg("public_key", key, "remove", "true")); err != nil {
		t.Fatal(err)
	}
	final := peer.rxBytes.Load()
	close(stop)
	<-sent
	<-drained
	after, err := pair[0].dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(after, "public_key="+key) {
		t.Fatal("peer still exposed")
	}
	if final <= scraped {
		t.Fatal("experiment did not transfer traffic in scrape/delete gap")
	}
	t.Logf("read/remove NOT finalization: scraped=%d retired=%d unreported_delta=%d delivered_during_delete=%d", scraped, final, final-scraped, delivered.Load())
}

func TestReceiptAllowedIPsNotQuiescence(t *testing.T) {
	pair := receiptPair(t)
	pair.Send(t, Ping, nil)
	peer, key := receiptPeer(t, pair[0].dev)
	if err := pair[0].dev.IpcSet(uapiCfg("public_key", key, "replace_allowed_ips", "true")); err != nil {
		t.Fatal(err)
	}
	before := peer.rxBytes.Load()
	for i := 0; i < 20; i++ {
		pair[1].tun.Outbound <- tuntest.Ping(pair[0].ip, pair[1].ip)
	}
	receiptAwait(t, func() bool { return peer.rxBytes.Load() > before })
	t.Logf("AllowedIPs clearing NOT quiescence: counters increased by %d", peer.rxBytes.Load()-before)
}

func TestReceiptDeviceDownRetainsCounters(t *testing.T) {
	pair := receiptPair(t)
	pair.Send(t, Ping, nil)
	peer, key := receiptPeer(t, pair[0].dev)
	pair.Send(t, Pong, nil)
	if err := pair[0].dev.Down(); err != nil {
		t.Fatal(err)
	}
	final := peer.rxBytes.Load()
	after, err := pair[0].dev.IpcGet()
	if err != nil || !strings.Contains(after, "public_key="+key) {
		t.Fatal("device Down lost retained counters")
	}
	for i := 0; i < 20; i++ {
		pair[1].tun.Outbound <- tuntest.Ping(pair[0].ip, pair[1].ip)
	}
	// Negative observation window, not a proof for all adapters or restarts.
	timer := time.NewTimer(200 * time.Millisecond)
	<-timer.C
	if peer.rxBytes.Load() != final {
		t.Fatal("counter changed after whole-device Down")
	}
	t.Logf("whole userspace device Down retained %d rx bytes; disrupts every peer; no durable receipt", final)
}
