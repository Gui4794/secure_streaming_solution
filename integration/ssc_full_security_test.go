package integration_test

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"secure_streaming_solution/config"
	streamcrypto "secure_streaming_solution/crypto"
	"secure_streaming_solution/protocol"
)

// Tests here launch the real Proxy/Server or a strictly authenticated fake peer.
// They never modify the project source code or use the committed identity keys.

type suiteLogs struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *suiteLogs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *suiteLogs) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

type suiteEnvironment struct {
	dir                                                        string
	serverPrivate                                              ed25519.PrivateKey
	proxyPrivate                                               ed25519.PrivateKey
	serverPrivFile, serverPubFile, proxyPrivFile, proxyPubFile string
	config                                                     config.ConfigOutput
	media                                                      []byte
}

func suiteWriteFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func suiteMakeIdentity(t *testing.T, dir, name string) (ed25519.PrivateKey, string, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	pubDer, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	privFile := filepath.Join(dir, name+"_identity.pem")
	pubFile := filepath.Join(dir, name+"_identity.pub.pem")
	suiteWriteFile(t, privFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	suiteWriteFile(t, pubFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer}))
	return private, privFile, pubFile
}
func suiteEnv(t *testing.T, mismatchConfig bool) suiteEnvironment {
	t.Helper()
	dir := t.TempDir()
	for _, sub := range []string{"config", "keys", "media"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"proxycrypto.config", "servercrypto.config"} {
		data, err := os.ReadFile(filepath.Join("..", "config", f))
		if err != nil {
			t.Fatal(err)
		}
		if mismatchConfig && f == "proxycrypto.config" {
			if !bytes.Contains(data, []byte("<IV>NULL</IV>")) {
				t.Fatal("IV config marker missing")
			}
			data = bytes.Replace(data, []byte("<IV>NULL</IV>"), []byte("<IV>CHANGED</IV>"), 1)
		}
		suiteWriteFile(t, filepath.Join(dir, "config", f), data)
	}
	srv, srvPriv, srvPub := suiteMakeIdentity(t, filepath.Join(dir, "keys"), "server")
	prx, prxPriv, prxPub := suiteMakeIdentity(t, filepath.Join(dir, "keys"), "proxy")
	media := make([]byte, 3809)
	if _, err := rand.Read(media); err != nil {
		t.Fatal(err)
	}
	suiteWriteFile(t, filepath.Join(dir, "media", "dante.mp4"), media)
	cfg := config.ConfigOutput{CipherAlgorithm: "AES", CipherMode: "GCM", IV: "NULL", IVSize: 96, Padding: "NULL", MacAlgorithm: "NULL", SymKeySize: 256}
	return suiteEnvironment{dir: dir, serverPrivate: srv, proxyPrivate: prx, serverPrivFile: srvPriv, serverPubFile: srvPub, proxyPrivFile: prxPriv, proxyPubFile: prxPub, config: cfg, media: media}
}
func suitePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
func suiteBuild(t *testing.T, pkg, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", path, pkg)
	cmd.Dir = ".."
	data, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, data)
	}
	return path
}
func suiteStart(t *testing.T, bin string, e suiteEnvironment, addEnv []string, args ...string) *suiteLogs {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = e.dir
	cmd.Env = append(os.Environ(), addEnv...)
	logs := &suiteLogs{}
	cmd.Stdout = logs
	cmd.Stderr = logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return logs
}
func suiteServer(t *testing.T, bin string, e suiteEnvironment, extraEnv ...string) (int, *suiteLogs) {
	t.Helper()
	p := suitePort(t)
	env := []string{"S3S_SERVER_IDENTITY_KEY=" + e.serverPrivFile, "S3S_TRUSTED_PROXY_KEY=" + e.proxyPubFile}
	logs := suiteStart(t, bin, e, append(env, extraEnv...), strconv.Itoa(p), filepath.Join(e.dir, "media"))
	suiteWait(t, logs, "Stream Server on")
	return p, logs
}
func suiteProxy(t *testing.T, bin string, e suiteEnvironment, serverPort int, extraEnv ...string) (int, *suiteLogs) {
	t.Helper()
	p := suitePort(t)
	env := []string{"S3S_PROXY_IDENTITY_KEY=" + e.proxyPrivFile, "S3S_TRUSTED_SERVER_KEY=" + e.serverPubFile}
	logs := suiteStart(t, bin, e, append(env, extraEnv...), strconv.Itoa(p), "127.0.0.1", strconv.Itoa(serverPort), "0")
	suiteWait(t, logs, "Proxy on")
	return p, logs
}
func suiteWait(t *testing.T, l *suiteLogs, part string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(l.String(), part) {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("expected log %q; got:\n%s", part, l.String())
}
func suiteGET(port int, name string) (int, []byte, error) {
	client := http.Client{Timeout: 7 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/video/%s", port, name))
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return resp.StatusCode, b, err
}
func suiteFakeHandshake(conn net.Conn, e suiteEnvironment) (*bufio.Reader, []byte, protocol.HandshakeType1, error) {
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	r := bufio.NewReader(conn)
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, protocol.HandshakeType1{}, err
	}
	if _, err = conn.Write(serverPriv.PublicKey().Bytes()); err != nil {
		return nil, nil, protocol.HandshakeType1{}, err
	}
	peerBytes := make([]byte, 32)
	if _, err = io.ReadFull(r, peerBytes); err != nil {
		return nil, nil, protocol.HandshakeType1{}, err
	}
	if err = protocol.AuthenticateX25519Server(r, conn, e.serverPrivate, e.proxyPrivate.Public().(ed25519.PublicKey), serverPriv.PublicKey().Bytes(), peerBytes); err != nil {
		return nil, nil, protocol.HandshakeType1{}, err
	}
	peer, err := ecdh.X25519().NewPublicKey(peerBytes)
	if err != nil {
		return nil, nil, protocol.HandshakeType1{}, err
	}
	secret, err := serverPriv.ECDH(peer)
	if err != nil {
		return nil, nil, protocol.HandshakeType1{}, err
	}
	aesKey, err := streamcrypto.DeriveAESKey(secret)
	if err != nil {
		return nil, nil, protocol.HandshakeType1{}, err
	}
	msg, err := protocol.ReadMessage(r)
	if err != nil {
		return nil, nil, protocol.HandshakeType1{}, err
	}
	p1, err := protocol.ParseHandshakeType1(msg)
	return r, aesKey, p1, err
}
func suiteReceiveProxyAlert(r io.Reader, key []byte, reason string) error {
	msg, err := protocol.ReadMessage(r)
	if err != nil {
		return fmt.Errorf("read Type255: %w", err)
	}
	got, err := protocol.ParseAuthenticatedErrorAlert(msg, key, protocol.AlertFromProxy)
	if err != nil {
		return fmt.Errorf("invalid authentication of Proxy Type255: %w", err)
	}
	if got != reason {
		return fmt.Errorf("Type255 reason got %q, want %q", got, reason)
	}
	return nil
}

type suiteAttack func(net.Conn, *bufio.Reader, []byte, protocol.HandshakeType3) error

func suiteRunFakePeer(t *testing.T, proxyBin string, e suiteEnvironment, attack suiteAttack) (*suiteLogs, error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverPort := ln.Addr().(*net.TCPAddr).Port
	result := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		r, key, p1, err := suiteFakeHandshake(conn, e)
		if err != nil {
			result <- err
			return
		}
		type2, challenge, err := protocol.CreateHandshakeType2(p1, e.config, key)
		if err != nil {
			result <- err
			return
		}
		if err = protocol.WriteMessage(conn, type2.Type, type2.Payload); err != nil {
			result <- err
			return
		}
		req, err := protocol.ReadMessage(r)
		if err != nil {
			result <- err
			return
		}
		p3, err := protocol.ParseHandshakeType3(req, p1.SequenceNumber+1, challenge, key)
		if err != nil {
			result <- fmt.Errorf("parse real Proxy Type 3: %w", err)
			return
		}
		result <- attack(conn, r, key, p3)
	}()
	proxyPort, proxyLogs := suiteProxy(t, proxyBin, e, serverPort)
	_, _, _ = suiteGET(proxyPort, "dante.mp4")
	select {
	case err = <-result:
		return proxyLogs, err
	case <-time.After(9 * time.Second):
		return proxyLogs, errors.New("fake peer timed out")
	}
}
func suiteRunFakeStage2(t *testing.T, proxyBin string, e suiteEnvironment, attack func(net.Conn, *bufio.Reader, []byte, protocol.HandshakeType1) error) (*suiteLogs, error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	result := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		r, key, p1, err := suiteFakeHandshake(conn, e)
		if err != nil {
			result <- err
			return
		}
		result <- attack(conn, r, key, p1)
	}()
	p, logs := suiteProxy(t, proxyBin, e, ln.Addr().(*net.TCPAddr).Port)
	_, _, _ = suiteGET(p, "dante.mp4")
	select {
	case err = <-result:
		return logs, err
	case <-time.After(9 * time.Second):
		return logs, errors.New("fake peer timed out")
	}
}
func suiteExpectFake(t *testing.T, logs *suiteLogs, err error, fragment string) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	suiteWait(t, logs, fragment)
}

func TestSSCEndToEndSecurity(t *testing.T) {
	serverBin := suiteBuild(t, "./stream-server", "ssc-stream-server")
	proxyBin := suiteBuild(t, "./stream-proxy", "ssc-proxy")

	t.Run("normal_streaming_exact_bytes_and_Type1_to_Type5", func(t *testing.T) {
		e := suiteEnv(t, false)
		port, _ := suiteServer(t, serverBin, e)
		p, logs := suiteProxy(t, proxyBin, e, port)
		status, body, err := suiteGET(p, "dante.mp4")
		if err != nil {
			t.Fatal(err)
		}
		if status != http.StatusOK {
			t.Fatalf("status %d", status)
		}
		if sha256.Sum256(body) != sha256.Sum256(e.media) {
			t.Fatalf("stream differs: received %d bytes, expected %d", len(body), len(e.media))
		}
		if strings.Contains(logs.String(), "error alert") || strings.Contains(logs.String(), "invalid Type") {
			t.Fatalf("unexpected protocol alert: %s", logs.String())
		}
	})
	t.Run("two_independent_streaming_sessions", func(t *testing.T) {
		e := suiteEnv(t, false)
		serverPort, _ := suiteServer(t, serverBin, e)
		proxyPort, _ := suiteProxy(t, proxyBin, e, serverPort)
		for attempt := 0; attempt < 2; attempt++ {
			status, got, err := suiteGET(proxyPort, "dante.mp4")
			if err != nil || status != http.StatusOK || !bytes.Equal(got, e.media) {
				t.Fatalf("session %d: status=%d bytes=%d err=%v", attempt+1, status, len(got), err)
			}
		}
	})
	t.Run("HTTP_bad_method_and_unknown_route", func(t *testing.T) {
		e := suiteEnv(t, false)
		p, _ := suiteProxy(t, proxyBin, e, suitePort(t))
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Post(fmt.Sprintf("http://127.0.0.1:%d/video/dante.mp4", p), "text/plain", strings.NewReader("x"))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("POST status: %d", resp.StatusCode)
		}
		resp, err = client.Get(fmt.Sprintf("http://127.0.0.1:%d/does-not-exist", p))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("unknown route status: %d", resp.StatusCode)
		}
	})
	t.Run("media_symlink_escape_authenticated_Type255", func(t *testing.T) {
		e := suiteEnv(t, false)
		suiteWriteFile(t, filepath.Join(e.dir, "secret.mp4"), []byte("secret"))
		if err := os.Symlink(filepath.Join(e.dir, "secret.mp4"), filepath.Join(e.dir, "media", "escape.mp4")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		port, _ := suiteServer(t, serverBin, e)
		p, logs := suiteProxy(t, proxyBin, e, port)
		_, _, _ = suiteGET(p, "escape.mp4")
		suiteWait(t, logs, "Authenticated Stream Server error alert: invalid or unavailable media")
	})
	t.Run("missing_media_authenticated_Type255", func(t *testing.T) {
		e := suiteEnv(t, false)
		port, _ := suiteServer(t, serverBin, e)
		p, logs := suiteProxy(t, proxyBin, e, port)
		_, _, _ = suiteGET(p, "missing.mp4")
		suiteWait(t, logs, "Authenticated Stream Server error alert: invalid or unavailable media")
	})
	t.Run("incompatible_crypto_configuration_authenticated_Type255", func(t *testing.T) {
		e := suiteEnv(t, true)
		port, _ := suiteServer(t, serverBin, e)
		p, logs := suiteProxy(t, proxyBin, e, port)
		_, _, _ = suiteGET(p, "dante.mp4")
		suiteWait(t, logs, "Authenticated Stream Server error alert: handshake negotiation failed")
	})
	t.Run("wrong_trusted_server_identity_MITM_rejected", func(t *testing.T) {
		e := suiteEnv(t, false)
		port, _ := suiteServer(t, serverBin, e)
		p, logs := suiteProxy(t, proxyBin, e, port, "S3S_TRUSTED_SERVER_KEY="+e.proxyPubFile)
		_, _, _ = suiteGET(p, "dante.mp4")
		suiteWait(t, logs, "X25519 authentication failed")
		if strings.Contains(logs.String(), "AES key derived") {
			t.Fatal("derived AES key after failed authentication")
		}
	})
	t.Run("wrong_proxy_identity_rejected_by_real_server", func(t *testing.T) {
		e := suiteEnv(t, false)
		port, serverLogs := suiteServer(t, serverBin, e)
		_, wrongPriv, _ := suiteMakeIdentity(t, filepath.Join(e.dir, "keys"), "untrusted_proxy")
		p, _ := suiteProxy(t, proxyBin, e, port, "S3S_PROXY_IDENTITY_KEY="+wrongPriv)
		_, _, _ = suiteGET(p, "dante.mp4")
		suiteWait(t, serverLogs, "X25519 authentication failed")
	})
	t.Run("missing_Server_identity_rejected", func(t *testing.T) {
		e := suiteEnv(t, false)
		port, serverLogs := suiteServer(t, serverBin, e, "S3S_SERVER_IDENTITY_KEY="+filepath.Join(e.dir, "missing.pem"))
		p, _ := suiteProxy(t, proxyBin, e, port)
		_, _, _ = suiteGET(p, "dante.mp4")
		suiteWait(t, serverLogs, "failed to load server identity")
	})
	t.Run("fake_Server_authenticated_Type255_accepted", func(t *testing.T) {
		e := suiteEnv(t, false)
		logs, err := suiteRunFakeStage2(t, proxyBin, e, func(c net.Conn, r *bufio.Reader, key []byte, _ protocol.HandshakeType1) error {
			return protocol.SendAuthenticatedErrorAlert(c, "test alert", key, protocol.AlertFromServer)
		})
		suiteExpectFake(t, logs, err, "Authenticated Stream Server error alert: test alert")
	})
	t.Run("fake_Server_plaintext_Type255_rejected", func(t *testing.T) {
		e := suiteEnv(t, false)
		logs, err := suiteRunFakeStage2(t, proxyBin, e, func(c net.Conn, r *bufio.Reader, key []byte, _ protocol.HandshakeType1) error {
			return protocol.WriteMessage(c, protocol.TypeError, []byte("fake error"))
		})
		suiteExpectFake(t, logs, err, "invalid or unauthenticated Type 255")
	})
	t.Run("fake_Server_wrong_direction_Type255_rejected", func(t *testing.T) {
		e := suiteEnv(t, false)
		logs, err := suiteRunFakeStage2(t, proxyBin, e, func(c net.Conn, r *bufio.Reader, key []byte, _ protocol.HandshakeType1) error {
			return protocol.SendAuthenticatedErrorAlert(c, "wrong direction", key, protocol.AlertFromProxy)
		})
		suiteExpectFake(t, logs, err, "invalid or unauthenticated Type 255")
	})
	t.Run("unexpected_Type2_causes_authenticated_Type255", func(t *testing.T) {
		e := suiteEnv(t, false)
		logs, err := suiteRunFakeStage2(t, proxyBin, e, func(c net.Conn, r *bufio.Reader, key []byte, _ protocol.HandshakeType1) error {
			if err := protocol.WriteMessage(c, protocol.TypeRequest, []byte("unexpected")); err != nil {
				return err
			}
			return suiteReceiveProxyAlert(r, key, "expected Type 2")
		})
		suiteExpectFake(t, logs, err, "expected Type 2")
	})
	t.Run("Type2_ciphertext_tampering_causes_authenticated_Type255", func(t *testing.T) {
		e := suiteEnv(t, false)
		logs, err := suiteRunFakeStage2(t, proxyBin, e, func(c net.Conn, r *bufio.Reader, key []byte, p1 protocol.HandshakeType1) error {
			m, _, err := protocol.CreateHandshakeType2(p1, e.config, key)
			if err != nil {
				return err
			}
			m.Payload[len(m.Payload)-1] ^= 0x01
			if err := protocol.WriteMessage(c, m.Type, m.Payload); err != nil {
				return err
			}
			return suiteReceiveProxyAlert(r, key, "invalid Type 2 payload")
		})
		suiteExpectFake(t, logs, err, "invalid Type 2 payload")
	})
	t.Run("invalid_Type1_causes_authenticated_Type255_from_real_Server", func(t *testing.T) {
		e := suiteEnv(t, false)
		port, _ := suiteServer(t, serverBin, e)
		if err := suiteRealServerAlert(e, port, func(c net.Conn, r *bufio.Reader, key []byte) error {
			if err := protocol.WriteMessage(c, protocol.TypeProposal, []byte{1}); err != nil {
				return err
			}
			return suiteReceiveServerAlert(r, key, "invalid Type 1 payload")
		}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("unexpected_Type1_causes_authenticated_Type255_from_real_Server", func(t *testing.T) {
		e := suiteEnv(t, false)
		port, _ := suiteServer(t, serverBin, e)
		if err := suiteRealServerAlert(e, port, func(c net.Conn, r *bufio.Reader, key []byte) error {
			if err := protocol.WriteMessage(c, protocol.TypeMediaBlock, []byte("unexpected")); err != nil {
				return err
			}
			return suiteReceiveServerAlert(r, key, "expected Type 1")
		}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("unexpected_Type3_causes_authenticated_Type255_from_real_Server", func(t *testing.T) {
		e := suiteEnv(t, false)
		port, _ := suiteServer(t, serverBin, e)
		if err := suiteRealServerAlert(e, port, func(c net.Conn, r *bufio.Reader, key []byte) error {
			proposal, _, err := protocol.CreateHandshakeType1(e.config)
			if err != nil {
				return err
			}
			if err = protocol.WriteMessage(c, proposal.Type, proposal.Payload); err != nil {
				return err
			}
			if _, err = protocol.ReadMessage(r); err != nil {
				return err
			}
			if err = protocol.WriteMessage(c, protocol.TypeMediaBlock, []byte("unexpected")); err != nil {
				return err
			}
			return suiteReceiveServerAlert(r, key, "expected Type 3")
		}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("path_traversal_in_Type3_rejected_by_real_Server", func(t *testing.T) {
		e := suiteEnv(t, false)
		port, _ := suiteServer(t, serverBin, e)
		if err := suiteRealServerAlert(e, port, func(c net.Conn, r *bufio.Reader, key []byte) error {
			proposal, seqX, err := protocol.CreateHandshakeType1(e.config)
			if err != nil {
				return err
			}
			if err = protocol.WriteMessage(c, proposal.Type, proposal.Payload); err != nil {
				return err
			}
			received, err := protocol.ReadMessage(r)
			if err != nil {
				return err
			}
			type2, err := protocol.ParseHandshakeType2(received, seqX, e.config, key)
			if err != nil {
				return err
			}
			bad, err := protocol.CreateHandshakeType3(type2, "../secret.mp4", key)
			if err != nil {
				return err
			}
			if err = protocol.WriteMessage(c, bad.Type, bad.Payload); err != nil {
				return err
			}
			return suiteReceiveServerAlert(r, key, "invalid Type 3 payload")
		}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("real_Server_receives_Proxy_Type255", func(t *testing.T) {
		e := suiteEnv(t, false)
		port, logs := suiteServer(t, serverBin, e)
		if err := suiteRealServerAlert(e, port, func(c net.Conn, r *bufio.Reader, key []byte) error {
			return protocol.SendAuthenticatedErrorAlert(c, "integration alert", key, protocol.AlertFromProxy)
		}); err != nil {
			t.Fatal(err)
		}
		suiteWait(t, logs, "Authenticated Proxy error alert: integration alert")
	})
	t.Run("invalid_Type3_causes_authenticated_Type255_from_real_Server", func(t *testing.T) {
		e := suiteEnv(t, false)
		port, _ := suiteServer(t, serverBin, e)
		if err := suiteRealServerAlert(e, port, func(c net.Conn, r *bufio.Reader, key []byte) error {
			m, seqX, err := protocol.CreateHandshakeType1(e.config)
			if err != nil {
				return err
			}
			if err = protocol.WriteMessage(c, m.Type, m.Payload); err != nil {
				return err
			}
			t2, err := protocol.ReadMessage(r)
			if err != nil {
				return err
			}
			parsed, err := protocol.ParseHandshakeType2(t2, seqX, e.config, key)
			if err != nil {
				return err
			}
			t3, err := protocol.CreateHandshakeType3(parsed, "dante.mp4", key)
			if err != nil {
				return err
			}
			t3.Payload[len(t3.Payload)-1] ^= 0x80
			if err = protocol.WriteMessage(c, t3.Type, t3.Payload); err != nil {
				return err
			}
			return suiteReceiveServerAlert(r, key, "invalid Type 3 payload")
		}); err != nil {
			t.Fatal(err)
		}
	})

	attacks := []struct {
		name, reason string
		action       suiteAttack
	}{
		{"Type4_tampering", "invalid Type 4 block", func(c net.Conn, r *bufio.Reader, k []byte, p3 protocol.HandshakeType3) error {
			msg, err := protocol.CreateType4Message(p3.SequenceNumber+1, []byte("abc"), k)
			if err != nil {
				return err
			}
			msg.Payload[len(msg.Payload)-1] ^= 1
			if err = protocol.WriteMessage(c, msg.Type, msg.Payload); err != nil {
				return err
			}
			return suiteReceiveProxyAlert(r, k, "invalid Type 4 block")
		}},
		{"Type4_truncated_payload", "invalid Type 4 payload", func(c net.Conn, r *bufio.Reader, k []byte, p3 protocol.HandshakeType3) error {
			if err := protocol.WriteMessage(c, protocol.TypeMediaBlock, []byte{0x01}); err != nil {
				return err
			}
			return suiteReceiveProxyAlert(r, k, "invalid Type 4 payload")
		}},
		{"Type4_replay", "invalid block sequence", func(c net.Conn, r *bufio.Reader, k []byte, p3 protocol.HandshakeType3) error {
			msg, err := protocol.CreateType4Message(p3.SequenceNumber+1, []byte("abc"), k)
			if err != nil {
				return err
			}
			for i := 0; i < 2; i++ {
				if err := protocol.WriteMessage(c, msg.Type, msg.Payload); err != nil {
					return err
				}
			}
			return suiteReceiveProxyAlert(r, k, "invalid block sequence")
		}},
		{"Type4_reordering", "invalid block sequence", func(c net.Conn, r *bufio.Reader, k []byte, p3 protocol.HandshakeType3) error {
			msg, err := protocol.CreateType4Message(p3.SequenceNumber+2, []byte("later"), k)
			if err != nil {
				return err
			}
			if err = protocol.WriteMessage(c, msg.Type, msg.Payload); err != nil {
				return err
			}
			return suiteReceiveProxyAlert(r, k, "invalid block sequence")
		}},
		{"unexpected_message_during_stream", "expected Type 4 or Type 5", func(c net.Conn, r *bufio.Reader, k []byte, p3 protocol.HandshakeType3) error {
			if err := protocol.WriteMessage(c, protocol.TypeProposal, []byte("injection")); err != nil {
				return err
			}
			return suiteReceiveProxyAlert(r, k, "expected Type 4 or Type 5")
		}},
		{"Type5_tampering", "invalid Type 5 end block", func(c net.Conn, r *bufio.Reader, k []byte, p3 protocol.HandshakeType3) error {
			msg, err := protocol.CreateType5Message(p3.SequenceNumber+1, k)
			if err != nil {
				return err
			}
			msg.Payload[len(msg.Payload)-1] ^= 0x22
			if err = protocol.WriteMessage(c, msg.Type, msg.Payload); err != nil {
				return err
			}
			return suiteReceiveProxyAlert(r, k, "invalid Type 5 end block")
		}},
		{"Type5_wrong_sequence", "invalid Type 5 end block", func(c net.Conn, r *bufio.Reader, k []byte, p3 protocol.HandshakeType3) error {
			msg, err := protocol.CreateType5Message(p3.SequenceNumber+2, k)
			if err != nil {
				return err
			}
			if err = protocol.WriteMessage(c, msg.Type, msg.Payload); err != nil {
				return err
			}
			return suiteReceiveProxyAlert(r, k, "invalid Type 5 end block")
		}},
	}
	for _, tt := range attacks {
		t.Run(tt.name, func(t *testing.T) {
			e := suiteEnv(t, false)
			logs, err := suiteRunFakePeer(t, proxyBin, e, tt.action)
			if err != nil {
				t.Fatal(err)
			}
			expectedLog := map[string]string{
				"Type4_tampering":                  "failed to decrypt Type 4",
				"Type4_truncated_payload":          "failed to unpack Type 4",
				"Type4_replay":                     "invalid sequence",
				"Type4_reordering":                 "invalid sequence",
				"unexpected_message_during_stream": "unexpected message Type",
				"Type5_tampering":                  "invalid Type 5",
				"Type5_wrong_sequence":             "invalid Type 5",
			}[tt.name]
			suiteWait(t, logs, expectedLog)
		})
	}
	t.Run("truncated_stream_without_Type5_detected", func(t *testing.T) {
		e := suiteEnv(t, false)
		logs, err := suiteRunFakePeer(t, proxyBin, e, func(c net.Conn, r *bufio.Reader, k []byte, p3 protocol.HandshakeType3) error {
			msg, err := protocol.CreateType4Message(p3.SequenceNumber+1, []byte("partial"), k)
			if err != nil {
				return err
			}
			if err = protocol.WriteMessage(c, msg.Type, msg.Payload); err != nil {
				return err
			}
			return c.Close()
		})
		if err != nil {
			t.Fatal(err)
		}
		suiteWait(t, logs, "error reading message")
	})
}
func suiteRealServerAlert(e suiteEnvironment, port int, attack func(net.Conn, *bufio.Reader, []byte) error) error {
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(7 * time.Second))
	r := bufio.NewReader(c)
	peerB := make([]byte, 32)
	if _, err = io.ReadFull(r, peerB); err != nil {
		return err
	}
	peer, err := ecdh.X25519().NewPublicKey(peerB)
	if err != nil {
		return err
	}
	me, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if _, err = c.Write(me.PublicKey().Bytes()); err != nil {
		return err
	}
	if err = protocol.AuthenticateX25519Proxy(r, c, e.proxyPrivate, e.serverPrivate.Public().(ed25519.PublicKey), peerB, me.PublicKey().Bytes()); err != nil {
		return err
	}
	secret, err := me.ECDH(peer)
	if err != nil {
		return err
	}
	key, err := streamcrypto.DeriveAESKey(secret)
	if err != nil {
		return err
	}
	return attack(c, r, key)
}
func suiteReceiveServerAlert(r io.Reader, key []byte, reason string) error {
	msg, err := protocol.ReadMessage(r)
	if err != nil {
		return err
	}
	got, err := protocol.ParseAuthenticatedErrorAlert(msg, key, protocol.AlertFromServer)
	if err != nil {
		return err
	}
	if got != reason {
		return fmt.Errorf("Server Type255 = %q, want %q", got, reason)
	}
	return nil
}
