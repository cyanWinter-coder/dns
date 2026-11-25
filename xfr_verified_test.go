package dns_test

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func uid530RR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("NewRR(%q): %v", s, err)
	}
	return rr
}

func uid530SOA(t *testing.T, serial uint32) *dns.SOA {
	t.Helper()
	rr := uid530RR(t, "example. 60 IN SOA ns.example. admin.example. "+
		"2024010101 7200 3600 1209600 60")
	soa := rr.(*dns.SOA)
	soa.Serial = serial
	return soa
}

func uid530A(t *testing.T) dns.RR {
	return uid530RR(t, "host.example. 60 IN A 192.0.2.10")
}

func uid530OldZone(t *testing.T) *dns.Zone {
	return dns.NewZone("example.", uid530SOA(t, 9), uid530A(t))
}

func startUID530RawServer(t *testing.T, handle func(*dns.Conn, *dns.Msg)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				dc := &dns.Conn{Conn: c}
				req, err := dc.ReadMsg()
				if err != nil {
					return
				}
				handle(dc, req)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func uid530Reply(req *dns.Msg, answers ...dns.RR) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	m.Answer = answers
	return m
}

func TestUID530SerialMismatchFailsImmediately(t *testing.T) {
	store := dns.NewZoneStore(uid530OldZone(t))
	x := store.Begin("example.", uint32(1))

	wrong := new(dns.Msg)
	wrong.Answer = []dns.RR{uid530SOA(t, 2)}
	err := x.ProcessMessage(uint64(1), wrong)
	if !errors.Is(err, dns.ErrSerialMismatch) {
		t.Fatalf("ProcessMessage error = %v, want ErrSerialMismatch", err)
	}

	var te *dns.TransferError
	if !errors.As(err, &te) {
		t.Fatalf("error %T is not *dns.TransferError", err)
	}
	if te.ExpectedSerial != 1 || te.ActualSerial != 2 {
		t.Fatalf("serial fields = expected %d/%d actual %d/%d",
			te.ExpectedSerial, te.WantSerial, te.ActualSerial, te.GotSerial)
	}
	if got := store.Current("example."); got.Serial != 9 {
		t.Fatalf("live zone serial changed to %d after serial failure", got.Serial)
	}
}

func TestUID530SequenceGapAbortsAndRetainsPrefix(t *testing.T) {
	store := dns.NewZoneStore(uid530OldZone(t))
	x := store.Begin("example.")

	first := new(dns.Msg)
	first.Answer = []dns.RR{uid530SOA(t, 3), uid530A(t)}
	if err := x.ProcessMessage(uint64(1), first); err != nil {
		t.Fatalf("seq 1: %v", err)
	}

	gap := new(dns.Msg)
	gap.Answer = []dns.RR{uid530RR(t, "two.example. 60 IN TXT \"missing next sequence\"")}
	err := x.ProcessMessage(uint64(3), gap)
	if !errors.Is(err, dns.ErrSequenceGap) {
		t.Fatalf("gap error = %v, want ErrSequenceGap", err)
	}

	var te *dns.TransferError
	if !errors.As(err, &te) {
		t.Fatalf("gap error %T is not TransferError", err)
	}
	if te.ExpectedSequence != 2 || te.ActualSequence != 3 {
		t.Fatalf("sequence fields expected 2 got %d/%d", te.ActualSequence, te.GotSequence)
	}
	if te.Partial == nil || len(te.Partial.Records) != 2 {
		t.Fatalf("partial = %#v, want two retained records", te.Partial)
	}
	if p := x.Partial(); p == nil || len(p.Received) != 2 {
		t.Fatalf("transaction partial = %#v, want two records", p)
	}
	if err := x.Commit(); !errors.Is(err, dns.ErrSequenceGap) {
		t.Fatalf("Commit after gap error = %v, want same fatal error", err)
	}
	if got := store.Current("example."); got.Serial != 9 || got.Len() != 2 {
		t.Fatalf("live zone changed after gap: serial=%d len=%d", got.Serial, got.Len())
	}
}

func TestUID530CommitOnlyAfterEndMarker(t *testing.T) {
	store := dns.NewZoneStore(uid530OldZone(t))
	x := store.Begin("example.")

	first := new(dns.Msg)
	first.Answer = []dns.RR{uid530SOA(t, 3), uid530A(t)}
	if err := x.ProcessMessage(1, first); err != nil {
		t.Fatal(err)
	}
	if err := x.Commit(); !errors.Is(err, dns.ErrIncompleteTransfer) {
		t.Fatalf("Commit without end marker = %v, want ErrIncompleteTransfer", err)
	}
	if got := store.Current("example."); got.Serial != 9 {
		t.Fatalf("old zone overwritten early, serial=%d", got.Serial)
	}

	end := new(dns.Msg)
	end.Answer = []dns.RR{uid530SOA(t, 3)}
	if err := x.ProcessMessage(2, end); err != nil {
		t.Fatal(err)
	}
	if err := x.Commit(); err != nil {
		t.Fatalf("Commit after end marker: %v", err)
	}
	got := store.Current("example.")
	if got == nil || got.Serial != 3 || got.Len() != 3 {
		t.Fatalf("committed zone = serial %d len %d, want 3/3", got.Serial, got.Len())
	}
}

func TestUID530PeerCloseIsIdentifiableAndAtomicOverNetwork(t *testing.T) {
	addr := startUID530RawServer(t, func(dc *dns.Conn, req *dns.Msg) {
		msg := uid530Reply(req, uid530SOA(t, 3), uid530A(t))
		if err := dc.WriteMsg(msg); err != nil {
			return
		}
		_ = dc.Close()
	})

	store := dns.NewZoneStore(uid530OldZone(t))
	tr := &dns.Transfer{ReadTimeout: time.Second, Store: store}
	q := new(dns.Msg)
	q.SetAxfr("example.")

	res, err := tr.VerifiedIn(q, addr)
	if err == nil {
		t.Fatal("VerifiedIn succeeded after peer close")
	}
	for _, target := range []error{dns.ErrIncompleteTransfer, io.EOF, io.ErrUnexpectedEOF, dns.ErrPeerClosed} {
		if !errors.Is(err, target) {
			t.Errorf("error %v does not match %v", err, target)
		}
	}
	if !dns.IsPeerClosed(err) {
		t.Error("IsPeerClosed = false, want true")
	}
	var te *dns.TransferError
	if !errors.As(err, &te) || te.Partial == nil || len(te.Partial.RRs) != 2 {
		t.Fatalf("error does not retain two-record partial: %#v", err)
	}
	if res == nil || res.Partial == nil || len(res.Partial.Received) != 2 {
		t.Fatalf("result partial missing: %#v", res)
	}
	if got := store.Current("example."); got.Serial != 9 {
		t.Fatalf("existing zone overwritten after disconnect: serial=%d", got.Serial)
	}

	// The legacy channel API remains usable and emits the identifiable error
	// before closing the channel.
	ch, err := new(dns.Transfer).In(q, addr)
	if err != nil {
		t.Fatal(err)
	}
	var channelErr error
	for env := range ch {
		if env.Error != nil {
			channelErr = env.Error
		}
	}
	if !errors.Is(channelErr, dns.ErrIncompleteTransfer) || !errors.Is(channelErr, io.EOF) {
		t.Fatalf("channel error = %v, want incomplete/EOF", channelErr)
	}
}

func TestUID530ReadTimeoutIsIdentifiable(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	addr := startUID530RawServer(t, func(dc *dns.Conn, req *dns.Msg) {
		<-release
	})

	tr := &dns.Transfer{ReadTimeout: 50 * time.Millisecond}
	q := new(dns.Msg)
	q.SetAxfr("example.")
	start := time.Now()
	_, err := tr.VerifiedIn(q, addr)
	if err == nil {
		t.Fatal("expected timeout")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("timeout took too long: %v", time.Since(start))
	}
	for _, target := range []error{dns.ErrTransferTimeout, context.DeadlineExceeded, os.ErrDeadlineExceeded} {
		if !errors.Is(err, target) {
			t.Errorf("error %v does not match %v", err, target)
		}
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("error %v is not a recognizable net timeout", err)
	}
	if !dns.IsTimeout(err) {
		t.Error("IsTimeout = false")
	}
}

func TestUID530NetworkSerialMismatch(t *testing.T) {
	addr := startUID530RawServer(t, func(dc *dns.Conn, req *dns.Msg) {
		_ = dc.WriteMsg(uid530Reply(req, uid530SOA(t, 2)))
		// Keep the connection open long enough to prove the client stopped.
		time.Sleep(time.Second)
	})

	tr := &dns.Transfer{ReadTimeout: time.Second, ExpectedSerial: 1, VerifySerial: true}
	q := new(dns.Msg)
	q.SetAxfr("example.")
	_, err := tr.VerifiedIn(q, addr)
	if !errors.Is(err, dns.ErrSerialMismatch) {
		t.Fatalf("err = %v, want ErrSerialMismatch", err)
	}
	var te *dns.TransferError
	if errors.As(err, &te) && (te.ExpectedSerial != 1 || te.ActualSerial != 2) {
		t.Fatalf("serial details = expected %d actual %d", te.ExpectedSerial, te.ActualSerial)
	}
}

func TestUID530LoneOpeningSOAIsNotEndMarker(t *testing.T) {
	store := dns.NewZoneStore(uid530OldZone(t))
	x := store.Begin("example.")
	soaOnly := new(dns.Msg)
	soaOnly.Answer = []dns.RR{uid530SOA(t, 3)}
	if err := x.ProcessMessage(1, soaOnly); err != nil {
		t.Fatal(err)
	}
	if err := x.Commit(); !errors.Is(err, dns.ErrIncompleteTransfer) {
		t.Fatalf("lone opening SOA Commit err=%v, want incomplete", err)
	}
	if got := store.Current("example."); got.Serial != 9 {
		t.Fatalf("store serial %d changed before closing SOA", got.Serial)
	}

	closing := new(dns.Msg)
	closing.Answer = []dns.RR{uid530SOA(t, 3)}
	if err := x.ProcessMessage(2, closing); err != nil {
		t.Fatal(err)
	}
	if err := x.Commit(); err != nil {
		t.Fatalf("Commit after closing SOA: %v", err)
	}
}

func TestUID530AutomaticProcessSequenceAndCommit(t *testing.T) {
	x := dns.NewAtomicTransfer("example.")
	if err := x.Process([]dns.RR{uid530SOA(t, 4), uid530A(t)}); err != nil {
		t.Fatal(err)
	}
	if err := x.Process(&dns.Envelope{RR: []dns.RR{uid530SOA(t, 4)}}); err != nil {
		t.Fatal(err)
	}
	z, err := x.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if z.Serial != 4 || z.Len() != 3 {
		t.Fatalf("zone serial=%d len=%d", z.Serial, z.Len())
	}
}

func TestUID530ConcurrentAutomaticSequencing(t *testing.T) {
	x := dns.NewAtomicTransfer("example.")
	if err := x.ProcessEnvelope(nil, &dns.Envelope{RR: []dns.RR{uid530SOA(t, 9)}}); err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 50)
	done := make(chan struct{})
	for i := 0; i < 50; i++ {
		go func() {
			rr := &dns.TXT{
				Hdr: dns.RR_Header{Name: "parallel.example.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{"x"},
			}
			errs <- x.ProcessEnvelope(nil, &dns.Envelope{RR: []dns.RR{rr}})
			done <- struct{}{}
		}()
	}
	for i := 0; i < 50; i++ {
		<-done
	}
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent automatic sequence: %v", err)
		}
	}
}

func TestUID530LargeSequencedTransferCommitsOnce(t *testing.T) {
	const n = 20000
	x := dns.NewAtomicTransfer("example.", uint32(7))
	opening := new(dns.Msg)
	opening.Answer = []dns.RR{uid530SOA(t, 7)}
	if err := x.ProcessMessage(1, opening); err != nil {
		t.Fatal(err)
	}

	seq := uint64(2)
	buf := make([]dns.RR, 0, 500)
	flush := func() {
		if len(buf) == 0 {
			return
		}
		m := new(dns.Msg)
		m.Answer = buf
		if err := x.ProcessMessage(seq, m); err != nil {
			t.Fatalf("seq %d: %v", seq, err)
		}
		seq++
		buf = make([]dns.RR, 0, 500)
	}
	for i := 0; i < n; i++ {
		buf = append(buf, &dns.A{
			Hdr: dns.RR_Header{Name: "h.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(192, 0, 2, byte(i%256)),
		})
		if len(buf) == 500 {
			flush()
		}
	}
	flush()

	end := new(dns.Msg)
	end.Answer = []dns.RR{uid530SOA(t, 7)}
	if err := x.ProcessMessage(seq, end); err != nil {
		t.Fatal(err)
	}
	z, err := x.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if z.Len() != n+2 || z.Serial != 7 {
		t.Fatalf("large zone len=%d serial=%d", z.Len(), z.Serial)
	}
}

func TestUID530SequenceTrackerGap(t *testing.T) {
	st := dns.NewSequenceTracker()
	if err := st.Check(0); err != nil {
		t.Fatal(err)
	}
	if err := st.Check(uint64(1)); err != nil {
		t.Fatal(err)
	}
	err := st.Check(3)
	if !errors.Is(err, dns.ErrSequenceGap) {
		t.Fatalf("Check(3) after 0,1 = %v, want gap", err)
	}
	var te *dns.TransferError
	if !errors.As(err, &te) || te.ExpectedSequence != 2 || te.ActualSequence != 3 {
		t.Fatalf("bad sequence error details: %#v", err)
	}
}

func TestUID530IXFREqualSerialCompletes(t *testing.T) {
	addr := startUID530RawServer(t, func(dc *dns.Conn, req *dns.Msg) {
		_ = dc.WriteMsg(uid530Reply(req, uid530SOA(t, 5)))
	})
	q := new(dns.Msg)
	q.SetIxfr("example.", 5, "ns.example.", "admin.example.")
	tr := &dns.Transfer{ReadTimeout: time.Second}
	res, err := tr.VerifiedIn(q, addr)
	if err != nil {
		t.Fatalf("equal serial IXFR: %v", err)
	}
	if !res.Complete || res.Zone == nil || res.Zone.Serial != 5 {
		t.Fatalf("unexpected result: %#v", res)
	}
}

func TestUID530IXFROlderSerialMismatch(t *testing.T) {
	addr := startUID530RawServer(t, func(dc *dns.Conn, req *dns.Msg) {
		_ = dc.WriteMsg(uid530Reply(req, uid530SOA(t, 4)))
	})
	q := new(dns.Msg)
	q.SetIxfr("example.", 5, "ns.example.", "admin.example.")
	tr := &dns.Transfer{ReadTimeout: time.Second, RequireSerialMatch: true}
	_, err := tr.VerifiedIn(q, addr)
	if !errors.Is(err, dns.ErrSerialMismatch) {
		t.Fatalf("older serial err=%v, want ErrSerialMismatch", err)
	}
}

func TestUID530SuccessfulAtomicNetworkTransfer(t *testing.T) {
	addr := startUID530RawServer(t, func(dc *dns.Conn, req *dns.Msg) {
		soa := uid530SOA(t, 3)
		if err := dc.WriteMsg(uid530Reply(req, soa)); err != nil {
			return
		}
		if err := dc.WriteMsg(uid530Reply(req, uid530A(t), uid530RR(t, "mx.example. 60 IN MX 10 mail.example."))); err != nil {
			return
		}
		if err := dc.WriteMsg(uid530Reply(req, soa)); err != nil {
			return
		}
	})

	store := dns.NewZoneStore(uid530OldZone(t))
	tr := &dns.Transfer{ReadTimeout: time.Second, Store: store}
	q := new(dns.Msg)
	q.SetAxfr("example.")
	res, err := tr.VerifiedIn(q, addr)
	if err != nil {
		t.Fatalf("VerifiedIn: %v", err)
	}
	if !res.Complete || res.Zone == nil || res.Zone.Len() != 4 {
		t.Fatalf("result = complete:%v zone:%v count:%d", res.Complete, res.Zone, res.Count)
	}
	got := store.Current("example.")
	if got == nil || got.Serial != 3 || got.Len() != 4 {
		t.Fatalf("store zone serial=%d len=%d, want 3/4", got.Serial, got.Len())
	}
}
