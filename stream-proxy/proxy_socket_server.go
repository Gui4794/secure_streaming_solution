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
)

/*
* in the context of secure streaming, the proxy is
* going to decrypt the media blocks. for now, keys and nonces
* are configured manually
* a version of diffie-hellman with authentication is to be implemented
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
		go handle(browser, originHost, originPort, time.Duration(delayMs)*time.Millisecond)
	}
}

func mustPort(value string) int {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		log.Fatalf("invalid port: %q", value)
	}
	return port
}

func handle(browser net.Conn, originHost string, originPort int, blockDelay time.Duration) {
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

	var rangeHeader string
	for {
		line, err := readLine(reader)
		if err != nil {
			return
		}
		if line == "" {
			break
		}
		if idx := strings.IndexByte(line, ':'); idx > 0 &&
			strings.EqualFold(line[:idx], "Range") {
			rangeHeader = strings.TrimSpace(line[idx+1:])
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
	relayFromOrigin(browser, originHost, originPort, name, rangeHeader, blockDelay)
}

func servePage(out io.Writer) {
	page := []byte(indexHTML)
	fmt.Fprintf(out, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(page))
	_, _ = out.Write(page)
}

// this function is what the proxy server does when talking to the stream server
func relayFromOrigin(browser io.Writer, originHost string, originPort int,
	name string, rangeHeader string, blockDelay time.Duration) {
	origin, err := net.Dial("tcp", net.JoinHostPort(originHost, strconv.Itoa(originPort)))
	if err != nil {
		writeSimpleStatus(browser, 502, "Bad Gateway")
		return
	}
	defer origin.Close()

	/*proxyPublicKey*/ _, proxyPrivateKey := generateKeyPair()
	sendPublicKey(proxyPrivateKey, origin)
		reader := bufio.NewReader(origin)
		streamPublicKey, err := receivePublicKey(reader)
		sharedSecret, err := establishSharedSecret(proxyPrivateKey, streamPublicKey)
		if(err != nil) {
			fmt.Println("something went wrong in computing the shared secret")
		}
		sharedKey, err := byteArrayToPublicKey(sharedSecret)
		if(err != nil) {
			fmt.Println("something went wrong while computing the shared key")
		}
	request := fmt.Sprintf("GET /media/%s HTTP/1.1\r\nHost: %s\r\n",
		name, net.JoinHostPort(originHost, strconv.Itoa(originPort)))
	if rangeHeader != "" {
		if strings.ContainsAny(rangeHeader, "\r\n") {
			writeSimpleStatus(browser, 400, "Bad Request")
			return
		}
		request += "Range: " + rangeHeader + "\r\n"
	}
	request += "Connection: close\r\n\r\n"
	if _, err := io.WriteString(origin, request); err != nil {
		writeSimpleStatus(browser, 502, "Bad Gateway")
		return
	}

	reader := bufio.NewReader(origin)
	statusLine, err := readLine(reader)
	if err != nil {
		writeSimpleStatus(browser, 502, "Bad Gateway")
		return
	}
	statusParts := strings.SplitN(statusLine, " ", 3)
	if len(statusParts) < 2 {
		writeSimpleStatus(browser, 502, "Bad Gateway")
		return
	}
	statusCode, err := strconv.Atoi(statusParts[1])
	if err != nil || statusCode < 100 || statusCode > 599 {
		writeSimpleStatus(browser, 502, "Bad Gateway")
		return
	}
	reason := ""
	if len(statusParts) > 2 {
		reason = strings.TrimSpace(statusParts[2])
	}

	contentLength := int64(-1)
	var contentType, contentRange, acceptRanges string
	for {
		line, err := readLine(reader)
		if err != nil {
			return
		}
		if line == "" {
			break
		}
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		value := strings.TrimSpace(line[idx+1:])
		switch key {
		case "content-length":
			contentLength, err = strconv.ParseInt(value, 10, 64)
			if err != nil || contentLength < 0 {
				writeSimpleStatus(browser, 502, "Bad Gateway")
				return
			}
		case "content-type":
			contentType = value
		case "content-range":
			contentRange = value
		case "accept-ranges":
			acceptRanges = value
		}
	}

	// Forward only the headers relevant to playback and range requests.
	fmt.Fprintf(browser, "HTTP/1.1 %d %s\r\n", statusCode, reason)
	if contentType != "" {
		fmt.Fprintf(browser, "Content-Type: %s\r\n", contentType)
	}
	if acceptRanges != "" {
		fmt.Fprintf(browser, "Accept-Ranges: %s\r\n", acceptRanges)
	}
	if contentRange != "" {
		fmt.Fprintf(browser, "Content-Range: %s\r\n", contentRange)
	}
	if contentLength >= 0 {
		fmt.Fprintf(browser, "Content-Length: %d\r\n", contentLength)
	}
	io.WriteString(browser, "Connection: close\r\n\r\n")

	if contentLength <= 0 {
		return
	}
	buf := make([]byte, blockSize)
	remaining := contentLength
	for remaining > 0 {
		toRead := int64(len(buf))
		if remaining < toRead {
			toRead = remaining
		}
		n, err := reader.Read(buf[:int(toRead)])
		if n > 0 {
			if blockDelay > 0 {
				time.Sleep(blockDelay)
			}
			if _, writeErr := browser.Write(buf[:n]); writeErr != nil {
				return
			}
			remaining -= int64(n)
		}
		if err != nil {
			return
		}
	}
}

func writeSimpleStatus(out io.Writer, code int, reason string) {
	fmt.Fprintf(out, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code, reason)
}
