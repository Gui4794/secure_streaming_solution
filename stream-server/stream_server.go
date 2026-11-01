package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"secure_streaming_solution/config"
	"secure_streaming_solution/crypto"
	"secure_streaming_solution/protocol"
)

/*
* in the context of secure streaming, the server is
* going to encrypt the media blocks. for now, keys and nonces
* are configured manually
* a version of diffie-hellman with authentication is to be implemented
 */

const (
	blockSize = 1024
)

func main() {
	configOutput, err := config.ParseConfigFile(config.StreamServer)
	if err != nil {
		log.Fatalf("Failed to read server config: %v", err)
	}

	// Validate the cryptographic configuration
	if err := configOutput.Validate(); err != nil {
		log.Fatalf("Invalid server crypto configuration: %v", err)
	}

	// TODO: remove these printlns once these variables are used
	cipherAlgorithm := configOutput.CipherAlgorithm
	fmt.Println(cipherAlgorithm)
	cipherMode := configOutput.CipherMode
	fmt.Println(cipherMode)
	iv := configOutput.IV
	fmt.Println(iv)
	ivSize := configOutput.IVSize
	fmt.Println(ivSize)
	padding := configOutput.Padding
	fmt.Println(padding)
	macAlgorithm := configOutput.MacAlgorithm
	fmt.Println(macAlgorithm)
	symKey := configOutput.SymKey
	fmt.Println(symKey)
	symKeySize := configOutput.SymKeySize
	fmt.Println(symKeySize)
	macKey := configOutput.MacKey
	fmt.Println(macKey)
	macKeySize := configOutput.MacKeySize
	fmt.Println(macKeySize)

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
		go handle(conn, root, configOutput)
	}
}

func handle(conn net.Conn, root string, serverConfig config.ConfigOutput) {
	defer conn.Close()

	/*
			* the server generates its private key
		    * as soon as the connection with the proxy is accepted
	*/
	streamPublicKey, streamPrivateKey := generateKeyPair()
	sendPublicKey(streamPublicKey, conn)
	reader := bufio.NewReader(conn)
	proxyPublicKey, err := receivePublicKey(reader)
	if err != nil {
		log.Printf("failed to receive proxy public key: %v", err)
		return
	}

	sharedSecret, err := establishSharedSecret(streamPrivateKey, proxyPublicKey)
	if err != nil {
		fmt.Println("something went wrong in computing the shared secret")
		return
	}

	aesKey, err := crypto.DeriveAESKey(sharedSecret)
	if err != nil {
		fmt.Println("failed to derive AES key:", err)
		return
	}

	fmt.Println("AES key derived:", len(aesKey), "bytes")

	//the stream server receives the handshakes and parses them

	// Receive Message Type 1
	type1Message, err := protocol.ReadMessage(reader)
	if err != nil {
		log.Printf("failed to receive type1: %v", err)
		return
	}
	if type1Message.Type != protocol.TypeProposal {

		if type1Message.Type == protocol.TypeError {
			log.Printf("Proxy error alert: %s", string(type1Message.Payload))
			return
		}

		log.Printf("expected Type 1, got Type %d", type1Message.Type)

		if err := protocol.SendErrorAlert(conn, "expected Type 1"); err != nil {
			log.Printf("failed to send Type 255: %v", err)
		}

		return
	}

	// Parse Type 1
	type1, err := protocol.ParseHandshakeType1(type1Message)
	if err != nil {
		log.Printf("invalid type1 payload: %v", err)

		if alertErr := protocol.SendErrorAlert(conn, "invalid Type 1 payload"); alertErr != nil {
			log.Printf("failed to send Type 255: %v", alertErr)
		}

		return
	}

	type2Message, challenge, err := protocol.CreateHandshakeType2(
		type1,
		serverConfig,
		aesKey,
	)
	if err != nil {
		log.Printf("failed to create type2: %v", err)
		return
	}

	//Send type 2 to proxy
	if err := protocol.WriteMessage(
		conn, type2Message.Type, type2Message.Payload,
	); err != nil {
		log.Printf("failed to send type2: %v", err)
		return
	}

	seqY := type1.SequenceNumber + 1

	//Type3 - receber e validar
	type3Message, err := protocol.ReadMessage(reader)
	if err != nil {
		log.Printf("failed to receive type3: %v", err)
		return
	}

	if type3Message.Type != protocol.TypeRequest {
		log.Printf("expected Type 3, got Type %d", type3Message.Type)
		return
	}

	type3, err := protocol.ParseHandshakeType3(
		type3Message, seqY, challenge, aesKey,
	)
	if err != nil {
		log.Printf("invalid type 3: %v", err)
		return
	}

	finalPath, err := resolveMediaPath(root, type3.Media)
	if err != nil {
		log.Printf("invalid or unavailable media: %v", err)
		return
	}

	firstSeqB := type3.SequenceNumber + 1

	serveFile(conn, aesKey, finalPath, firstSeqB)
}

func resolveMediaPath(root, name string) (string, error) {

	if name == "" || strings.ContainsAny(name, "\x00\r\n") {
		return "", fmt.Errorf("invalid media filename")
	}

	name = filepath.FromSlash(name)

	if filepath.IsAbs(name) {
		return "", fmt.Errorf("absolute media paths are not allowed")
	}

	filePath := filepath.Join(root, name)

	rel, err := filepath.Rel(root, filePath)
	if err != nil ||
		rel == ".." ||
		strings.HasPrefix(rel, ".."+string(os.PathSeparator)) ||
		filepath.IsAbs(rel) {
		return "", fmt.Errorf("media path escapes media directory")
	}

	finalPath, err := filepath.EvalSymlinks(filePath)
	if err != nil {
		return "", fmt.Errorf("cannot resolve media path: %w", err)
	}

	rel, err = filepath.Rel(root, finalPath)
	if err != nil ||
		rel == ".." ||
		strings.HasPrefix(rel, ".."+string(os.PathSeparator)) ||
		filepath.IsAbs(rel) {
		return "", fmt.Errorf("media symlink escapes media directory")
	}

	info, err := os.Stat(finalPath)
	if err != nil {
		return "", fmt.Errorf("cannot access media: %w", err)
	}

	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("media is not a regular file")
	}

	return finalPath, nil
}

// parseRange accepts a single HTTP bytes range (start-end, start-, or -suffix).
// Like the Java source, malformed ranges fall back to the entire file.
// Unsatisfiable ranges produce a 416 response.

// i think we might need to change this, on itttt ass beatriz

func serveFile(out io.Writer, aesKey []byte, path string, firstSeqB uint64) {
	file, err := os.Open(path)
	if err != nil {
		log.Printf("Failed to open video: %v", err)
		return
	}
	defer file.Close()

	plaintext := make([]byte, blockSize)
	sequenceNumber := firstSeqB

	for {
		// Read the next video block
		bytesRead, readErr := file.Read(plaintext)

		if bytesRead > 0 {
			// Create encrypted Type 4 payload
			type4Msg, err := protocol.CreateType4Message(
				sequenceNumber,
				plaintext[:bytesRead],
				aesKey,
			)
			if err != nil {
				log.Printf("Failed to create Type 4: %v", err)
				return
			}

			if err := protocol.WriteMessage(
				out,
				protocol.TypeMediaBlock,
				type4Msg.Payload,
			); err != nil {
				log.Printf("Failed to send Type 4: %v", err)
				return
			}

			sequenceNumber++
		}

		if readErr == io.EOF {
			break
		}

		if readErr != nil {
			log.Printf("Failed to read video: %v", readErr)
			return
		}
	} //fim do ciclo 4
	//type 5

	type5Message, err := protocol.CreateType5Message(sequenceNumber, aesKey)
	if err != nil {
		log.Printf("Failed to create Type 5: %v", err)
		return
	}

	if err := protocol.WriteMessage(
		out,
		type5Message.Type,
		type5Message.Payload,
	); err != nil {
		log.Printf("Failed to send Type 5: %v", err)
		return
	}
}

/*
 * Helper function that reads contents from a socket (conn)
 * and tries to parse it into a  Type 1 Message
 * note that this assumes that the configs
 * are correct and validated
 */

/*
 * Helper that checks if a given message is valid,
 * according to the config file.
 * note that this assumes that the configs
 * are correct and validated
 * could this be moved to a different file? maybe
 */
