package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"secure_streaming_solution/config"
	"secure_streaming_solution/crypto"
	"secure_streaming_solution/protocol"
	//"golang.org/x/text/message"
)

/*
* in the context of secure streaming, the proxy is
* going to decrypt the media blocks
 */

const indexHTML = `<!doctype html>
<html><head><meta charset="utf-8"><title>MP4 via socket-only proxy</title></head>
<body style="font-family:sans-serif;max-width:900px;margin:2rem auto">
  <h1>MP4 streamed through a plain-socket proxy</h1>
  <p>File: <input id="f" value="dante.mp4">
     <button onclick="load()">Load</button></p>
  <video id="v" controls preload="metadata" style="width:100%"></video>
  <script>
    function load() {
      const v = document.getElementById('v');
      v.src = '/video/' + encodeURIComponent(document.getElementById('f').value);
      v.load();
    }
    load();
  </script>
</body></html>`

func main() {
	proxyConfigOutput, err := config.ParseConfigFile(config.ProxyServer)
	if err != nil {
		log.Fatalf("Failed to read proxy config: %v", err)
	}

	// Validate the cryptographic configuration
	if err := proxyConfigOutput.Validate(); err != nil {
		log.Fatalf("Invalid proxy crypto configuration: %v", err)
	}

	port := 8080
	originHost := "localhost"
	originPort := 8081
	delayMs := 2000
	showExperiments := 0

	if len(os.Args) > 1 {
		port = mustPort(os.Args[1])
	}
	if len(os.Args) > 2 {
		originHost = os.Args[2]
	}
	if len(os.Args) > 3 {
		originPort = mustPort(os.Args[3])
	}
	if len(os.Args) > 4 {
		var err error
		delayMs, err = strconv.Atoi(os.Args[4])
		if err != nil || delayMs < 0 {
			log.Fatal("blockDelayMs must be a nonnegative integer")
		}
		if len(os.Args) > 5 {
			showExperiments, err = strconv.Atoi(os.Args[5])
			if err != nil || (showExperiments != 0 && showExperiments != 1) {
				log.Fatal("showExperiments must be either 0 or 1")
			}
		}
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	log.Printf("Proxy on http://localhost:%d/ -> http://%s:%d (delay %dms/block)",
		port, originHost, originPort, delayMs)

	for {
		browser, err := listener.Accept()
		if err != nil {
			log.Printf("Accept failed: %v", err)
			continue
		}
		go handle(browser, originHost, originPort, time.Duration(delayMs)*time.Millisecond, proxyConfigOutput, showExperiments)
	}
}

func mustPort(value string) int {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		log.Fatalf("invalid port: %q", value)
	}
	return port
}

func handle(browser net.Conn, originHost string, originPort int, blockDelay time.Duration, config config.ConfigOutput, showExperiments int) {
	defer browser.Close()

	reader := bufio.NewReader(browser)
	requestLine, err := readLine(reader)
	if err != nil || !strings.HasPrefix(requestLine, "GET ") {
		writeSimpleStatus(browser, 400, "Bad Request")
		return
	}
	parts := strings.Fields(requestLine)
	if len(parts) < 2 {
		writeSimpleStatus(browser, 400, "Bad Request")
		return
	}
	path := parts[1]

	for {
		line, err := readLine(reader)
		if err != nil {
			return
		}
		if line == "" {
			break
		}
	}

	if path == "/" || path == "" {
		servePage(browser)
		return
	}
	if !strings.HasPrefix(path, "/video/") {
		writeSimpleStatus(browser, 404, "Not Found")
		return
	}

	name := strings.TrimPrefix(path, "/video/")
	// Never allow untrusted request bytes to inject new HTTP headers.
	if name == "" || strings.ContainsAny(name, "\r\n") {
		writeSimpleStatus(browser, 400, "Bad Request")
		return
	}
	relayFromOrigin(browser, originHost, originPort, name, blockDelay, config, showExperiments)
}

func servePage(out io.Writer) {
	page := []byte(indexHTML)
	fmt.Fprintf(out, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(page))
	_, _ = out.Write(page)
}

// this function is what the proxy server does when talking to the stream server
func relayFromOrigin(browser io.Writer, originHost string, originPort int,
	name string, blockDelay time.Duration, proxyConfig config.ConfigOutput, showExperiments int,
) {
	origin, err := net.Dial("tcp", net.JoinHostPort(originHost, strconv.Itoa(originPort)))
	if err != nil {
		writeSimpleStatus(browser, 502, "Bad Gateway")
		return
	}
	defer origin.Close()

	proxyPublicKey, proxyPrivateKey := generateKeyPair()
	sendPublicKey(proxyPublicKey, origin)
	reader := bufio.NewReader(origin)
	streamPublicKey, err := receivePublicKey(reader)
	if err != nil {
		log.Printf("failed to receive server key: %v", err)
		writeSimpleStatus(browser, 502, "Bad Gateway")
		return
	}
	proxyKeyPath := os.Getenv("S3S_PROXY_IDENTITY_KEY")
	if proxyKeyPath == "" {
		proxyKeyPath = "keys/proxy_identity.pem"
	}

	serverKeyPath := os.Getenv("S3S_TRUSTED_SERVER_KEY")
	if serverKeyPath == "" {
		serverKeyPath = "keys/server_identity.pub.pem"
	}

	proxyIdentity, err := protocol.LoadEd25519PrivateKey(proxyKeyPath)
	if err != nil {
		log.Printf("failed to load Proxy identity: %v", err)
		writeSimpleStatus(browser, 502, "Bad Gateway")
		return
	}

	trustedServerIdentity, err := protocol.LoadEd25519PublicKey(serverKeyPath)
	if err != nil {
		log.Printf("failed to load trusted Stream Server identity: %v", err)
		writeSimpleStatus(browser, 502, "Bad Gateway")
		return
	}

	if err := protocol.AuthenticateX25519Proxy(
		reader, origin, proxyIdentity, trustedServerIdentity,
		streamPublicKey.Bytes(), proxyPublicKey.Bytes(),
	); err != nil {
		log.Printf("X25519 authentication failed: %v", err)
		writeSimpleStatus(browser, 502, "Bad Gateway")
		return
	}

	sharedSecret, err := establishSharedSecret(proxyPrivateKey, streamPublicKey)
	if err != nil {
		log.Printf("failed to compute shared secret: %v", err)
		writeSimpleStatus(browser, 502, "Bad Gateway")
		return
	}
	aesKey, err := crypto.DeriveAESKey(sharedSecret)
	if err != nil {
		log.Printf("failed to derive AES key: %v", err)
		writeSimpleStatus(browser, 502, "Bad Gateway")
		return
	}

	mediaKey, err := crypto.DeriveMediaKey(sharedSecret, proxyConfig.SymKeySize)
	if err != nil {
		log.Printf("failed to derive media key: %v", err)
		writeSimpleStatus(browser, 502, "Bad Gateway")
		return
	}

	block, err := crypto.CreateAcmCipher(mediaKey)
	if err != nil {
		writeSimpleStatus(browser, 502, "Bad Gateway")
		return
	}

	fmt.Println("AES key derived:", len(aesKey), "bytes")

	sendAlert := func(reason string) {
		if err := protocol.SendAuthenticatedErrorAlert(
			origin, reason, aesKey, protocol.AlertFromProxy,
		); err != nil {
			log.Printf("failed to send authenticated Type 255: %v", err)
		}
	}

	var alertReplayGuard protocol.AlertReplayGuard
	receiveAlert := func(msg protocol.Message) {
		reason, err := alertReplayGuard.ParseAuthenticatedErrorAlertOnce(
			msg, aesKey, protocol.AlertFromServer,
		)
		if err != nil {
			log.Printf("invalid or unauthenticated Type 255: %v", err)
			return
		}
		log.Printf("Authenticated Stream Server error alert: %s", reason)
	}

	// sends type 1 message to the stream server
	type1Msg, seqX, err := protocol.CreateHandshakeType1(proxyConfig)
	if err != nil {
		log.Println("error in sending type 1 message (proxy)")
		return
	}
	if err := protocol.WriteMessage(
		origin,
		type1Msg.Type,
		type1Msg.Payload,
	); err != nil {
		log.Printf("failed to send Type 1: %v", err)
		return
	}

	// reads the type 2 message
	// Receive Type 2
	type2Msg, err := protocol.ReadMessage(reader)
	if err != nil {
		log.Printf("failed to read Type 2: %v", err)
		return
	}

	// Handle Type 255 error alert
	if type2Msg.Type == protocol.TypeError {
		receiveAlert(type2Msg)
		return
	}

	// Reject unexpected message types
	if type2Msg.Type != protocol.TypeConfirmation {
		log.Printf("expected Type 2, got Type %d", type2Msg.Type)
		sendAlert("expected Type 2")
		return
	}

	type2, err := protocol.ParseHandshakeType2(type2Msg, seqX, proxyConfig, aesKey)
	if err != nil {
		log.Printf("invalid Type 2 payload: %v", err)
		sendAlert("invalid Type 2 payload")
		return
	}

	// sends the type 3 message
	type3Msg, err := protocol.CreateHandshakeType3(type2, name, aesKey)
	if err != nil {
		log.Println("error in creating type 3 message (proxy)")
		sendAlert("cannot create Type 3")
		return
	}
	if err := protocol.WriteMessage(
		origin,
		type3Msg.Type,
		type3Msg.Payload,
	); err != nil {
		log.Printf("failed to send Type 3: %v", err)
		return
	}

	// keeps sending the content until it reaches eof (type 5)
	fmt.Fprintf(browser, "HTTP/1.1 200 OK\r\nContent-Type: video/mp4\r\n\r\n")

	// SEQB1 = SEQZ + 1 = SEQY + 2
	expectedSeq := type2.SequenceNumber + 2

	var encryptedBlocks int
	var decryptedBlocks int
	var encryptedBytes int64
	var decryptedBytes int64
	startTime := time.Now()

	for {
		type4Or5Msg, err := protocol.ReadMessage(reader)
		if err != nil {
			log.Printf("error reading message (proxy): %v", err)
			return
		}

		// Handle Type 255 error alert
		if type4Or5Msg.Type == protocol.TypeError {
			receiveAlert(type4Or5Msg)
			return
		}

		// Reject unexpected message types
		if type4Or5Msg.Type != protocol.TypeMediaBlock &&
			type4Or5Msg.Type != protocol.TypeEndBlock {

			log.Printf("unexpected message Type %d", type4Or5Msg.Type)
			sendAlert("expected Type 4 or Type 5")
			return
		}

		// Handle Type 5 - End of stream
		if type4Or5Msg.Type == protocol.TypeEndBlock {
			if err := protocol.ParseType5Message(
				type4Or5Msg, expectedSeq, mediaKey,
			); err != nil {
				log.Printf("invalid Type 5: %v", err)
				sendAlert("invalid Type 5 end block")
				return
			}
			break
		}

		// Unpack Type 4 payload
		encryptedBlocks++
		encryptedBytes += int64(len(type4Or5Msg.Payload))
		seqNumber, nonce, cipherTextPlusMac, err := crypto.UnpackContents(type4Or5Msg.Payload)
		if err != nil {
			log.Printf("failed to unpack Type 4: %v", err)
			sendAlert("invalid Type 4 payload")
			return
		}

		// Decrypt and authenticate Type 4
		decryptedContents, err := crypto.DecryptBlock(cipherTextPlusMac, block, nonce, seqNumber)
		if err != nil {
			log.Printf("failed to decrypt Type 4: %v", err)
			sendAlert("invalid Type 4 block")
			return
		}

		// Validate block sequence number
		if seqNumber != expectedSeq {
			log.Printf("invalid sequence: expected %d, got %d", expectedSeq, seqNumber)
			sendAlert("invalid block sequence")
			return
		}
		expectedSeq++

		// Send decrypted block to browser
		n, err := browser.Write(decryptedContents)
		if err != nil {
			log.Printf("failed to send block to browser: %v", err)
			return
		}
		if n != len(decryptedContents) {
			log.Printf("incomplete block write: %d of %d bytes", n, len(decryptedContents))
			return
		}

		decryptedBlocks++
		decryptedBytes += int64(n)

		if blockDelay > 0 {
			time.Sleep(blockDelay)
		}
	}

	elapsed := time.Since(startTime).Seconds()
	var throughputKBps float64
	if elapsed > 0 {
		throughputKBps = float64(decryptedBytes) / 1000 / elapsed
	}

	if showExperiments == 1 {
		log.Println("===== STREAMING METRICS =====")
		log.Printf("Encrypted Type 4 blocks received: %d", encryptedBlocks)
		log.Printf("Decrypted blocks forwarded: %d", decryptedBlocks)
		log.Printf("Encrypted Type 4 payload volume: %d bytes", encryptedBytes)
		log.Printf("Decrypted video bytes forwarded: %d bytes", decryptedBytes)
		log.Printf("Duration (after Type 3 through validated Type 5): %.3f s", elapsed)
		log.Printf("Video throughput: %.2f kB/s", throughputKBps)
		log.Println("=============================")
	}
}

func writeSimpleStatus(out io.Writer, code int, reason string) {
	fmt.Fprintf(out, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code, reason)
}
