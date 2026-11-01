package integration_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
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

	streamcrypto "secure_streaming_solution/crypto"
	"secure_streaming_solution/protocol"
)

type safeLog struct {
	sync.Mutex
	data bytes.Buffer
}

func (l *safeLog) Write(p []byte) (int, error) {
	l.Lock()
	defer l.Unlock()
	return l.data.Write(p)
}

func (l *safeLog) String() string {
	l.Lock()
	defer l.Unlock()
	return l.data.String()
}

func waitForLog(t *testing.T, logs *safeLog, part string) {
	t.Helper()
	until := time.Now().Add(8 * time.Second)
	for time.Now().Before(until) {
		if strings.Contains(logs.String(), part) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("não apareceu %q nos logs:\n%s", part, logs.String())
}

func buildBinary(t *testing.T, name, pkg string) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", binary, pkg)
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build %s falhou: %v\n%s", pkg, err, output)
	}
	return binary
}

func startBinary(t *testing.T, binary, dir string, args ...string) *safeLog {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Dir = dir
	logs := &safeLog{}
	cmd.Stdout = logs
	cmd.Stderr = logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return logs
}

func unusedTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func newRuntimeDir(t *testing.T, incompatible bool) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "config"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "media"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"proxycrypto.config", "servercrypto.config"} {
		data, err := os.ReadFile(filepath.Join("..", "config", name))
		if err != nil {
			t.Fatal(err)
		}
		if incompatible && name == "proxycrypto.config" {
			if !bytes.Contains(data, []byte("<IV>NULL</IV>")) {
				t.Fatal("não encontrei a configuração IV esperada")
			}
			data = bytes.Replace(data, []byte("<IV>NULL</IV>"), []byte("<IV>DIFFERENT</IV>"), 1)
		}
		if err := os.WriteFile(filepath.Join(root, "config", name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func triggerBrowserRequest(t *testing.T, proxyPort int) {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/video/sample.mp4", proxyPort))
	// When the handshake fails, the Proxy may close without an HTTP response.
	if err == nil {
		_ = response.Body.Close()
	}
}

func TestType255Integration(t *testing.T) {
	proxyBin := buildBinary(t, "secure-proxy", "./stream-proxy")
	serverBin := buildBinary(t, "secure-stream-server", "./stream-server")

	t.Run("real_server_to_real_proxy", func(t *testing.T) {
		dir := newRuntimeDir(t, true)
		serverPort, proxyPort := unusedTCPPort(t), unusedTCPPort(t)
		serverLogs := startBinary(t, serverBin, dir,
			strconv.Itoa(serverPort), filepath.Join(dir, "media"))
		waitForLog(t, serverLogs, "Stream Server on")

		proxyLogs := startBinary(t, proxyBin, dir,
			strconv.Itoa(proxyPort), "127.0.0.1", strconv.Itoa(serverPort), "0")
		waitForLog(t, proxyLogs, "Proxy on")
		triggerBrowserRequest(t, proxyPort)

		// The real Server rejects the proposed configuration with an encrypted alert.
		// The real Proxy must decrypt and authenticate that alert.
		waitForLog(t, proxyLogs,
			"Authenticated Stream Server error alert: handshake negotiation failed")
	})

	t.Run("real_server_receives_authenticated_proxy_alert", func(t *testing.T) {
		dir := newRuntimeDir(t, false)
		serverPort := unusedTCPPort(t)
		serverLogs := startBinary(t, serverBin, dir,
			strconv.Itoa(serverPort), filepath.Join(dir, "media"))
		waitForLog(t, serverLogs, "Stream Server on")

		if err := sendAlertToRealServer(serverPort); err != nil {
			t.Fatal(err)
		}
		waitForLog(t, serverLogs, "Authenticated Proxy error alert: integration test")
	})

	t.Run("real_proxy_rejects_forged_alert", func(t *testing.T) {
		dir := newRuntimeDir(t, false)
		fakeServer, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer fakeServer.Close()
		fakeServerPort := fakeServer.Addr().(*net.TCPAddr).Port

		result := make(chan error, 1)
		go func() {
			result <- mockServerSendsForgedAlert(fakeServer)
		}()

		proxyPort := unusedTCPPort(t)
		proxyLogs := startBinary(t, proxyBin, dir,
			strconv.Itoa(proxyPort), "127.0.0.1", strconv.Itoa(fakeServerPort), "0")
		waitForLog(t, proxyLogs, "Proxy on")
		triggerBrowserRequest(t, proxyPort)

		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(6 * time.Second):
			t.Fatal("timeout ao enviar Type 255 falsificado")
		}
		waitForLog(t, proxyLogs, "invalid or unauthenticated Type 255")
		if strings.Contains(proxyLogs.String(), "Authenticated Stream Server error alert") {
			t.Fatal("Proxy aceitou um alerta com a direção errada")
		}
	})

	t.Run("real_proxy_sends_authenticated_alert", func(t *testing.T) {
		dir := newRuntimeDir(t, false)
		fakeServer, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer fakeServer.Close()
		fakeServerPort := fakeServer.Addr().(*net.TCPAddr).Port

		result := make(chan error, 1)
		go func() {
			result <- mockServerGetsProxyAlert(fakeServer)
		}()

		proxyPort := unusedTCPPort(t)
		proxyLogs := startBinary(t, proxyBin, dir,
			strconv.Itoa(proxyPort), "127.0.0.1", strconv.Itoa(fakeServerPort), "0")
		waitForLog(t, proxyLogs, "Proxy on")
		triggerBrowserRequest(t, proxyPort)

		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(6 * time.Second):
			t.Fatal("timeout à espera do Type 255 autenticado do Proxy")
		}
	})
}

func mockServerGetsProxyAlert(listener net.Listener) error {
	conn, key, err := fakeServerHandshake(listener)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Intentionally send Type 3 instead of Type 2.
	if err := protocol.WriteMessage(conn, protocol.TypeRequest, []byte("unexpected")); err != nil {
		return err
	}
	alert, err := protocol.ReadMessage(conn)
	if err != nil {
		return fmt.Errorf("reading Proxy's Type 255: %w", err)
	}
	reason, err := protocol.ParseAuthenticatedErrorAlert(alert, key, protocol.AlertFromProxy)
	if err != nil {
		return fmt.Errorf("authenticating Proxy's Type 255: %w", err)
	}
	if reason != "expected Type 2" {
		return fmt.Errorf("unexpected authenticated reason: %q", reason)
	}
	return nil
}

func mockServerSendsForgedAlert(listener net.Listener) error {
	conn, key, err := fakeServerHandshake(listener)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Wrong direction: a real server must use AlertFromServer.
	return protocol.SendAuthenticatedErrorAlert(
		conn, "forged alert", key, protocol.AlertFromProxy,
	)
}

func fakeServerHandshake(listener net.Listener) (net.Conn, []byte, error) {
	conn, err := listener.Accept()
	if err != nil {
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))

	// Same real X25519 + HKDF exchange as the two applications.
	success := false
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()
	proxyPubBytes := make([]byte, 32)
	if _, err = io.ReadFull(conn, proxyPubBytes); err != nil {
		return nil, nil, fmt.Errorf("reading Proxy public key: %w", err)
	}
	proxyPub, err := ecdh.X25519().NewPublicKey(proxyPubBytes)
	if err != nil {
		return nil, nil, err
	}
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if _, err = conn.Write(serverPriv.PublicKey().Bytes()); err != nil {
		return nil, nil, err
	}
	secret, err := serverPriv.ECDH(proxyPub)
	if err != nil {
		return nil, nil, err
	}
	key, err := streamcrypto.DeriveAESKey(secret)
	if err != nil {
		return nil, nil, err
	}

	proposal, err := protocol.ReadMessage(conn)
	if err != nil {
		return nil, nil, err
	}
	if proposal.Type != protocol.TypeProposal {
		return nil, nil, fmt.Errorf("expected Type 1; got %d", proposal.Type)
	}

	success = true
	return conn, key, nil
}

func sendAlertToRealServer(port int) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Server sends its public key first; Proxy sends its public key next.
	serverPublicBytes := make([]byte, 32)
	if _, err := io.ReadFull(conn, serverPublicBytes); err != nil {
		return err
	}
	serverPublic, err := ecdh.X25519().NewPublicKey(serverPublicBytes)
	if err != nil {
		return err
	}
	proxyPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if _, err := conn.Write(proxyPrivate.PublicKey().Bytes()); err != nil {
		return err
	}
	secret, err := proxyPrivate.ECDH(serverPublic)
	if err != nil {
		return err
	}
	key, err := streamcrypto.DeriveAESKey(secret)
	if err != nil {
		return err
	}
	return protocol.SendAuthenticatedErrorAlert(
		conn, "integration test", key, protocol.AlertFromProxy,
	)
}
