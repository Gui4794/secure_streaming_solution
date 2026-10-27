package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"secure_streaming_solution/crypto"
	"strconv"
	"strings"
)

/*
* in the context of secure streaming, the server is
* going to encrypt the media blocks. for now, keys and nonces
* are configured manually
* a version of diffie-hellman with authentication is to be implemented
 */

const blockSize = 1024

func main() {
	port := 8081
	mediaDir := "media"
	if len(os.Args) > 1 {
		value, err := strconv.Atoi(os.Args[1])
		if err != nil || value < 1 || value > 65535 {
			log.Fatalf("invalid server port: %q", os.Args[1])
		}
		port = value
	}
	if len(os.Args) > 2 {
		mediaDir = os.Args[2]
	}

	root, err := filepath.Abs(mediaDir)
	if err != nil {
		log.Fatal(err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		log.Fatalf("media directory unavailable: %v", err)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	log.Printf("Stream Server on http://localhost:%d/media/<file.mp4> (dir: %s)", port, root)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		// Equivalent to Java's thread pool: one goroutine per connection.
		go handle(conn, root)
	}
}

func handle(conn net.Conn, root string) {
	defer conn.Close()

	/*
	the server could generate its private key
	as soon as the connection with the proxy is accepted
	*/
	/*streamPublicKey*/
	streamPublicKey, streamPrivateKey := generateKeyPair()
	sendPublicKey(streamPublicKey, conn)
	reader := bufio.NewReader(conn)
	proxyPublicKey, err := receivePublicKey(reader)
	sharedSecret, err := establishSharedSecret(streamPrivateKey, proxyPublicKey)
	if err != nil {
		fmt.Println("something went wrong in computing the shared secret")
	}
	aesKey, err := crypto.DeriveAESKey(sharedSecret)
	if err != nil {
		fmt.Println("failed to derive AES key:", err)
		return
	}

	fmt.Println("AES key derived:", len(aesKey), "bytes")
	requestLine, err := readLine(reader)
	if err != nil {
		writeStatus(conn, 400, "Bad Request", 0, "")
		return
	}
	requestParts := strings.Fields(requestLine)
	if len(requestParts) != 3 || requestParts[0] != "GET" || !strings.HasPrefix(requestParts[2], "HTTP/1.") {
		writeStatus(conn, 400, "Bad Request", 0, "")
		return
	}
	path := requestParts[1]

	var rangeHeader string
	for {
		line, err := readLine(reader)
		if err != nil {
			return
		}
		if line == "" {
			break
		}
		if colon := strings.IndexByte(line, ':'); colon > 0 && strings.EqualFold(line[:colon], "Range") {
			rangeHeader = strings.TrimSpace(line[colon+1:])
		}
	}

	if !strings.HasPrefix(path, "/media/") {
		writeStatus(conn, 404, "Not Found", 0, "")
		return
	}
	// Decode percent-encoded filenames (e.g. "my%20movie.mp4"). Reject
	// directory traversal, including encoded traversal and symlink escapes.
	name, err := url.PathUnescape(strings.TrimPrefix(path, "/media/"))
	if err != nil || name == "" || strings.ContainsAny(name, "\x00\r\n") {
		writeStatus(conn, 400, "Bad Request", 0, "")
		return
	}
	filePath := filepath.Join(root, filepath.FromSlash(name))
	rel, err := filepath.Rel(root, filePath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		writeStatus(conn, 404, "Not Found", 0, "")
		return
	}
	finalPath, err := filepath.EvalSymlinks(filePath)
	if err != nil {
		writeStatus(conn, 404, "Not Found", 0, "")
		return
	}
	rel, err = filepath.Rel(root, finalPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		writeStatus(conn, 404, "Not Found", 0, "")
		return
	}
	info, err := os.Stat(finalPath)
	if err != nil || !info.Mode().IsRegular() {
		writeStatus(conn, 404, "Not Found", 0, "")
		return
	}
	serveFile(conn, aesKey, finalPath, info.Size(), rangeHeader)
}

// parseRange accepts a single HTTP bytes range (start-end, start-, or -suffix).
// Like the Java source, malformed ranges fall back to the entire file.
// Unsatisfiable ranges produce a 416 response.
func parseRange(header string, size int64) (start, end int64, partial, unsatisfiable bool) {
	start, end = 0, size-1
	if !strings.HasPrefix(header, "bytes=") || strings.Contains(header, ",") {
		return
	}
	fields := strings.Split(strings.TrimSpace(strings.TrimPrefix(header, "bytes=")), "-")
	if len(fields) != 2 || (fields[0] == "" && fields[1] == "") {
		return
	}
	var s, e int64
	var err error
	if fields[0] == "" {
		var suffix int64
		suffix, err = strconv.ParseInt(fields[1], 10, 64)
		if err != nil || suffix < 0 {
			return
		}
		s = size - suffix
		if s < 0 {
			s = 0
		}
		e = size - 1
	} else {
		s, err = strconv.ParseInt(fields[0], 10, 64)
		if err != nil || s < 0 {
			return
		}
		e = size - 1
		if fields[1] != "" {
			e, err = strconv.ParseInt(fields[1], 10, 64)
			if err != nil || e < 0 {
				return
			}
			if e >= size {
				e = size - 1
			}
		}
	}
	if s > e || s >= size {
		return 0, 0, false, true
	}
	return s, e, true, false
}

func serveFile(out io.Writer, aesKey []byte, path string, size int64, rangeHeader string) {
	start, end, partial, unsatisfiable := parseRange(rangeHeader, size)
	if unsatisfiable {
		writeStatus(out, 416, "Range Not Satisfiable", 0,
			fmt.Sprintf("Content-Range: bytes */%d\r\n", size))
		return
	}
	length := size
	code, reason := 200, "OK"
	extra := "Accept-Ranges: bytes\r\n"
	if partial {
		length = end - start + 1
		code, reason = 206, "Partial Content"
		extra += fmt.Sprintf("Content-Range: bytes %d-%d/%d\r\n", start, end, size)
	}

	file, err := os.Open(path)
	if err != nil {
		writeStatus(out, 404, "Not Found", 0, "")
		return
	}
	defer file.Close()
	if _, err := file.Seek(start, io.SeekStart); err != nil {
		return
	}

	writeHeaders(out, code, reason, length, "video/mp4", extra)
	// Use a 1024-byte buffer to send the file without buffering it entirely.
	/*
	 * from my understanding, io.CopyBuffer is doing a for loop (i checked its source code).
	 * a possible implementation would be to make this process more manual: we craft the block,
	 * encrypt it, and send it, though i am not sure if this would work
	 */
	var plaintext []byte = make([]byte, blockSize)
	for {
			//everytime we do this, the plaintext buffer gets the bytes read
			bytesRead, err := file.Read(plaintext)
			if err != nil && err != io.EOF {
				panic(err)
			} else if err == io.EOF || bytesRead == int(length) {
				break
			}
			//now the idea is to use the AES-GCM library to encrypt this, and then send it
			var sequenceNumber uint64 = 1

			block, err := crypto.CreateAcmCipher(aesKey)
			if err != nil {
				panic(err)
			}
			nonce := crypto.GenerateNonce()
			encryptedBlock, err := crypto.EncryptBlock(plaintext, block, nonce, sequenceNumber)
			if err != nil {
				panic(err)
			}
			out.Write(encryptedBlock)

		}

	_, _ = io.CopyBuffer(out, io.LimitReader(file, length), make([]byte, blockSize)) //para apagar quando tivermos a função de cima
}

func writeStatus(out io.Writer, code int, reason string, length int64, extra string) {
	writeHeaders(out, code, reason, length, "", extra)
}

// cria e envia os cabeçalhos HTTP do Stream Server para o Proxy
func writeHeaders(out io.Writer, code int, reason string, length int64, contentType, extra string) {
	fmt.Fprintf(out, "HTTP/1.1 %d %s\r\n", code, reason)

	if contentType != "" {
		fmt.Fprintf(out, "Content-Type: %s\r\n", contentType) // content-type ex: video/mp4
	}

	fmt.Fprintf(out, "Content-Length: %d\r\nConnection: close\r\n", length)

	if extra != "" {
		io.WriteString(out, extra)
	}

	io.WriteString(out, "\r\n")
}
