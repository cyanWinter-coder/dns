package dns

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func cloneSignatureVerifyBytes(b []byte) []byte {
	cp := make([]byte, len(b))
	copy(cp, b)
	return cp
}

func decodeSignatureVerifyWireMsg(t *testing.T, tm uint64) []byte {
	t.Helper()
	msgData, err := hex.DecodeString(fmt.Sprintf(wireMsg, tm))
	if err != nil {
		t.Fatal(err)
	}
	return msgData
}

func TestSignatureVerifyUID532TsigImmutableRepeatable(t *testing.T) {
	m := newTsig(HmacSHA256)
	buf, _, err := TsigGenerate(m, testSecret, "", false)
	if err != nil {
		t.Fatal(err)
	}

	original := cloneSignatureVerifyBytes(buf)
	if err := TsigVerify(buf, testSecret, "", false); err != nil {
		t.Fatalf("first verification failed: %v", err)
	}
	if !bytes.Equal(buf, original) {
		t.Fatal("TsigVerify modified the original message")
	}
	if err := TsigVerify(buf, testSecret, "", false); err != nil {
		t.Fatalf("second verification failed: %v", err)
	}
	if !bytes.Equal(buf, original) {
		t.Fatal("repeated TsigVerify modified the original message")
	}
}

func TestSignatureVerifyUID532TsigClassification(t *testing.T) {
	t.Run("unknown key", func(t *testing.T) {
		msgData := decodeSignatureVerifyWireMsg(t, timeSigned)
		err := tsigVerify(msgData, tsigSecretProvider(map[string]string{}), "", false, timeSigned)
		if !errors.Is(err, ErrSecret) {
			t.Fatalf("expected ErrSecret, got %v", err)
		}
		if !IsUnknownKey(err) {
			t.Fatalf("IsUnknownKey did not classify %v", err)
		}
	})

	t.Run("mac mismatch", func(t *testing.T) {
		wrongSecret := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		msgData := decodeSignatureVerifyWireMsg(t, timeSigned)
		err := tsigVerify(msgData, tsigHMACProvider(wrongSecret), "", false, timeSigned)
		if !errors.Is(err, ErrSig) {
			t.Fatalf("expected ErrSig, got %v", err)
		}
		if !IsMACMismatch(err) {
			t.Fatalf("IsMACMismatch did not classify %v", err)
		}
		if IsTimeSkew(err) || IsUnknownKey(err) {
			t.Fatalf("MAC error misclassified as another category: %v", err)
		}
	})

	t.Run("covered byte change is mac mismatch", func(t *testing.T) {
		msg := newTsig(HmacSHA256)
		buf, _, err := TsigGenerate(msg, testSecret, "", false)
		if err != nil {
			t.Fatal(err)
		}
		tampered := cloneSignatureVerifyBytes(buf)
		tampered[13] ^= 0x01 // first question-label character
		if err := TsigVerify(tampered, testSecret, "", false); !errors.Is(err, ErrSig) {
			t.Fatalf("expected ErrSig after covered-byte modification, got %v", err)
		}
	})

	t.Run("additional record without tsig", func(t *testing.T) {
		msg := new(Msg)
		msg.SetQuestion("example.org.", TypeA)
		msg.SetEdns0(4096, true)
		msgData, err := msg.Pack()
		if err != nil {
			t.Fatal(err)
		}
		if err := tsigVerify(msgData, tsigHMACProvider(testSecret), "", false, timeSigned); !errors.Is(err, ErrNoSig) {
			t.Fatalf("expected ErrNoSig, got %v", err)
		}
	})
}

func TestSignatureVerifyUID532TimeErrorDelta(t *testing.T) {
	for _, now := range []uint64{timeSigned + 301, timeSigned - 301} {
		wantDelta := int64(now) - int64(timeSigned)
		msgData := decodeSignatureVerifyWireMsg(t, timeSigned)
		err := tsigVerify(msgData, tsigHMACProvider(testSecret), "", false, now)
		if !errors.Is(err, ErrTime) {
			t.Fatalf("expected ErrTime, got %v", err)
		}
		if !IsTimeSkew(err) {
			t.Fatalf("IsTimeSkew did not classify %v", err)
		}

		var skew *TimeOffsetError
		if !errors.As(err, &skew) {
			t.Fatalf("expected *TimeOffsetError, got %T %v", err, err)
		}
		if skew.ServerUnix != int64(now) || skew.ClientUnix != int64(timeSigned) {
			t.Fatalf("unexpected times: server=%d client=%d", skew.ServerUnix, skew.ClientUnix)
		}
		if skew.Delta != time.Duration(wantDelta)*time.Second {
			t.Fatalf("expected delta %ds, got %s", wantDelta, skew.Delta)
		}
		if skew.AbsoluteDelta != 301*time.Second {
			t.Fatalf("expected absolute delta 301s, got %s", skew.AbsoluteDelta)
		}
		if skew.Fudge != 300*time.Second {
			t.Fatalf("expected fudge 300s, got %s", skew.Fudge)
		}
		if text := err.Error(); !strings.Contains(text, fmt.Sprintf("%ds", wantDelta)) || !strings.Contains(text, "server-client time difference") {
			t.Fatalf("error %q does not contain signed server-client delta %ds", text, wantDelta)
		}
	}
}

func TestSignatureVerifyUID532SIG0ReadOnlyRepeatable(t *testing.T) {
	keyRR := new(KEY)
	keyRR.Hdr.Name = "ed25519.example."
	keyRR.Hdr.Rrtype = TypeKEY
	keyRR.Hdr.Class = ClassINET
	keyRR.Algorithm = ED25519
	privateKey, err := keyRR.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		t.Fatalf("generated key %T does not implement crypto.Signer", privateKey)
	}

	msg := new(Msg)
	msg.SetQuestion("sig0-isolation.example.", TypeSOA)
	now := uint32(time.Now().Unix())
	sigRR := new(SIG)
	sigRR.Hdr.Name = "."
	sigRR.Hdr.Rrtype = TypeSIG
	sigRR.Hdr.Class = ClassANY
	sigRR.Algorithm = ED25519
	sigRR.Expiration = now + 300
	sigRR.Inception = now - 300
	sigRR.KeyTag = keyRR.KeyTag()
	sigRR.SignerName = keyRR.Hdr.Name

	buf, err := sigRR.Sign(signer, msg)
	if err != nil {
		t.Fatal(err)
	}
	original := cloneSignatureVerifyBytes(buf)

	if err := sigRR.Verify(keyRR, buf); err != nil {
		t.Fatalf("first SIG(0) verification failed: %v", err)
	}
	if !bytes.Equal(buf, original) {
		t.Fatal("SIG(0) Verify modified the signed message")
	}
	if err := sigRR.Verify(keyRR, buf); err != nil {
		t.Fatalf("second SIG(0) verification failed: %v", err)
	}
	if !bytes.Equal(buf, original) {
		t.Fatal("repeated SIG(0) Verify modified the signed message")
	}
}

func TestSignatureVerifyUID532TCPIsolation(t *testing.T) {
	keyRR := new(KEY)
	keyRR.Hdr.Name = "ed25519.example."
	keyRR.Hdr.Rrtype = TypeKEY
	keyRR.Hdr.Class = ClassINET
	keyRR.Algorithm = ED25519
	privateKey, err := keyRR.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		t.Fatalf("generated key %T does not implement crypto.Signer", privateKey)
	}

	sign := func(id uint16) []byte {
		msg := new(Msg)
		msg.Id = id
		msg.SetQuestion(fmt.Sprintf("req-%d.sig0-isolation.example.", id), TypeSOA)
		now := uint32(time.Now().Unix())
		sigRR := new(SIG)
		sigRR.Hdr.Name = "."
		sigRR.Hdr.Rrtype = TypeSIG
		sigRR.Hdr.Class = ClassANY
		sigRR.Algorithm = ED25519
		sigRR.Expiration = now + 300
		sigRR.Inception = now - 300
		sigRR.KeyTag = keyRR.KeyTag()
		sigRR.SignerName = keyRR.Hdr.Name
		buf, err := sigRR.Sign(signer, msg)
		if err != nil {
			t.Fatalf("sign request %d: %v", id, err)
		}
		return buf
	}

	bad := sign(1)
	// Byte 13 is inside the question name and remains parseable, while it
	// changes the bytes covered by SIG(0).
	bad[13]++
	good := sign(2)

	srv, addr, _, err := RunLocalTCPServer(":0", func(s *Server) {
		s.Handler = HandlerFunc(func(w ResponseWriter, r *Msg) {
			var sig *SIG
			for _, rr := range r.Extra {
				if candidate, ok := rr.(*SIG); ok {
					sig = candidate
					break
				}
			}

			verified := false
			if sig != nil {
				raw, packErr := r.Pack()
				if packErr != nil {
					t.Errorf("pack request for SIG(0) verification: %v", packErr)
				} else {
					verified = sig.Verify(keyRR, raw) == nil
				}
			}

			resp := new(Msg)
			resp.SetRcode(r, RcodeSuccess)
			if !verified {
				resp.Rcode = RcodeNotAuth
			}
			if err := w.WriteMsg(resp); err != nil {
				t.Errorf("write response: %v", err)
			}
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	readResponse := func() (*Msg, error) {
		var length uint16
		if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
			return nil, err
		}
		raw := make([]byte, length)
		if _, err := io.ReadFull(conn, raw); err != nil {
			return nil, err
		}
		resp := new(Msg)
		return resp, resp.Unpack(raw)
	}

	for _, tc := range []struct {
		name     string
		packet   []byte
		wantCode int
	}{
		{"bad sig0", bad, RcodeNotAuth},
		{"good sig0", good, RcodeSuccess},
	} {
		if err := binary.Write(conn, binary.BigEndian, uint16(len(tc.packet))); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(tc.packet); err != nil {
			t.Fatal(err)
		}
		resp, err := readResponse()
		if err != nil {
			t.Fatalf("%s: read response: %v", tc.name, err)
		}
		if resp.Rcode != tc.wantCode {
			t.Fatalf("%s: expected rcode %d, got %d", tc.name, tc.wantCode, resp.Rcode)
		}
	}
}

func TestSignatureVerifyUID532RepeatedTSIGOnOneConnection(t *testing.T) {
	secret := map[string]string{"example.": testSecret}
	srv, addr, _, err := RunLocalTCPServer(":0", func(s *Server) {
		s.TsigSecret = secret
		s.Handler = HandlerFunc(func(w ResponseWriter, r *Msg) {
			if status := w.TsigStatus(); status != nil {
				t.Errorf("server TSIG status for id %d: %v", r.Id, status)
			}
			resp := new(Msg)
			resp.SetReply(r)
			if r.IsTsig() != nil && w.TsigStatus() == nil {
				resp.SetTsig("example.", HmacSHA256, 300, time.Now().Unix())
			}
			if err := w.WriteMsg(resp); err != nil {
				t.Errorf("write TSIG response: %v", err)
			}
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown()

	client := &Client{Net: "tcp", TsigSecret: secret}
	conn, err := client.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	for i := 0; i < 2; i++ {
		msg := newTsig(HmacSHA256)
		resp, _, err := client.ExchangeWithConn(msg, conn)
		if err != nil {
			t.Fatalf("exchange %d on reused connection: %v", i, err)
		}
		if resp.Rcode != RcodeSuccess {
			t.Fatalf("exchange %d: unexpected rcode %d", i, resp.Rcode)
		}
	}
}
