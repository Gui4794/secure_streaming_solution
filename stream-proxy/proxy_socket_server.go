package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"io"

	"secure_streaming_solution/config"
	"secure_streaming_solution/crypto"
	"secure_streaming_solution/protocol"

	//"golang.org/x/text/message"
)

/*
* in the context of secure streaming, the proxy is
* going to decrypt the media blocks
 */

const blockSize = 1024

const indexHTML = `<!doctype html>
<html><head><meta charset="utf-8"><title>MP4 via socket-only proxy</title></head>
<body style="font-family:sans-serif;max-width:900px;margin:2rem auto">
  <h1>MP4 streamed through a plain-socket proxy</h1>
  <p>File: <input id="f" value="sample.mp4">
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
	delayMs := 2000 // Preserves the 2-second delay per block in the supplied Java.

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
		go handle(browser, originHost, originPort, time.Duration(delayMs)*time.Millisecond, proxyConfigOutput)
	}
}

func mustPort(value string) int {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		log.Fatalf("invalid port: %q", value)
	}
	return port
}

func handle(browser net.Conn, originHost string, originPort int, blockDelay time.Duration, config config.ConfigOutput) {
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
	relayFromOrigin(browser, originHost, originPort, name, blockDelay, config)
}

func servePage(out io.Writer) {
	page := []byte(indexHTML)
	fmt.Fprintf(out, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(page))
	_, _ = out.Write(page)
}
// this function is what the proxy server does when talking to the stream server
func relayFromOrigin(browser io.Writer, originHost string, originPort int,
	name string, blockDelay time.Duration, proxyConfig config.ConfigOutput,
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

	block, err := crypto.CreateAcmCipher(aesKey)
	if err != nil {
		writeSimpleStatus(browser, 502, "Bad Gateway")
		return
	}

	fmt.Println("AES key derived:", len(aesKey), "bytes")
	//sends type 1 message to the stream server
	type1Msg, seqX, err := protocol.CreateHandshakeType1(proxyConfig)
	if err != nil {
		log.Println("error in sending type 1 message (proxy)")
		return
	}
	protocol.WriteMessage(origin, type1Msg.Type, type1Msg.Payload)
	if err != nil {
		log.Println(err.Error())
		return
	}

	//reads the type 2 message
	type2Msg, err := protocol.ReadMessage(origin)
	if err != nil {
		log.Println("error in reading type 2 message (proxy)")
	}

	type2, err := protocol.ParseHandshakeType2(type2Msg, seqX, proxyConfig, aesKey)
	if err != nil {
		log.Println("error in converting type2 message (proxy")
		return
	}

	//sends the type 3 message
	type3Msg, err := protocol.CreateHandshakeType3(type2, name, aesKey)
	if err != nil {
		log.Println("error in creating type 3 message (proxy)")
		return
	}
	err = protocol.WriteMessage(origin, type3Msg.Type, type3Msg.Payload)
	if err != nil {
		log.Println("error while writing type 3 message (proxy)")
	}

	//keeps sending the content until it reaches eof (type 5)
	fmt.Fprintf(browser, "HTTP/1.1 200 OK\r\nContent-Type: video/mp4\r\n\r\n")
	for {
		type4Or5Msg, err := protocol.ReadMessage(origin)
		if err != nil {
			log.Println("error in reading message (proxy)")
			return
		}
		if (type4Or5Msg.Type != protocol.TypeMediaBlock && type4Or5Msg.Type != protocol.TypeEndBlock) {
			//type 255 handling could go here
			log.Println("received message is neither type 4 or 5")
		}
		if type4Or5Msg.Type == protocol.TypeEndBlock {
			break
		}
		seqNumber, nonce, cipherTextPlusMac, err := crypto.UnpackContents(type4Or5Msg.Payload)
		if err != nil {
			log.Println("error while unpacking the received block (proxy)")
			return
		}
		decryptedContents, err := crypto.DecryptBlock(cipherTextPlusMac, block, nonce, seqNumber)
		if err != nil {
			log.Println("error while decrypting the received block (proxy)")
		}
		_, err = browser.Write(decryptedContents)
		if err != nil {
			log.Println("error while sending to browser (proxy)")
			return
		}
		if (blockDelay > 0) {
			time.Sleep(blockDelay)
		}
	}

}

func writeSimpleStatus(out io.Writer, code int, reason string) {
	fmt.Fprintf(out, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code, reason)
}
