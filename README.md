# Secure Streaming Solution

## Index

- [Context](#context)
- [Project Structure](#project-structure)
- [How to Compile and Run](#how-to-compile-and-run)

## Context

This assignment consists of a secure implementation of a streaming protocol: starting from the Java files written by our professor (Henrique Domingos), which concerned an insecure streaming solution, we were tasked with implementing security mechanisms and properties to make this a secure protocol, such as protection against Man-In-The-Middle Attacks, Message Reordering Attacks, Message Tampering Attacks, as well as some others. Together, we decided to build this project in Go, so we converted the given Java files to Go (using AI).

## Project Structure

The relevant parts of the project structure are as follows:

```
.
├── config
│   ├── config_reader.go
│   ├── proxycrypto.config
│   ├── servercrypto.config
│   └── servercrypto.config.backup
├── crypto
│   ├── aes_gcm.go
│   ├── diffie_hellman.go
│   └── key_derivation.go
├── go.mod
├── go.sum
├── integration
│   └── ssc_full_security_test.go
├── keys
│   ├── proxy_identity.pub.pem
│   └── server_identity.pub.pem
├── media
│   └── dante.mp4
├── protocol
│   ├── handshake_type1.go
│   ├── handshake_type2.go
│   ├── handshake_type3.go
│   ├── identity_keys.go
│   ├── message.go
│   ├── ssc_protocol_security_test.go
│   ├── type255.go
│   ├── type4_message.go
│   ├── type5.go
│   ├── x25519_auth.go
│   └── x25519_auth_handshake.go
├── README.md
├── run_secure_streaming.sh
├── stream-proxy
│   ├── http_util.go
│   ├── key_exchange.go
│   └── proxy_socket_server.go
├── stream-server
│   ├── http_util.go
│   ├── key_exchange.go
│   └── stream_server.go
```

More specifically, this project holds several different directories:

- `config`: reads and processes the configuration files
- `crypto`: stores everything related to cryptography
- `keys`: a persistent way of storing the keys of the servers
- `media`: holds the server's movie(s) to be streamed
- `protocol`: everything related to the handshakes betwen servers, in order to establish cryptographic parameters and perform message exchanges.

And the main two points of this project:

- `stream-proxy`: the bridge between the stream server and the browser: it decrypts the blocks sent from the stream server and delivers them to the browser.
- `stream-server`: hosts the file that the user wants to stream: it ciphers the file's blocks and securely sends it to the proxy server;

## How to Compile and Run

### Requirements

Every machine that is to run this program needs to [download the Go programming language and its compiler](https://go.dev/doc/install). The earliest version we tested this on was go 1.22.0.

### Locally (both servers on one machine)

Looking at the [project structure](#project-structure), you might have noticed a file called `run_secure_streaming.sh`. This is how you run our program. It makes use of the `go run` function to automatically compile and run all the necessary programs. More interestingly, optional arguments are supported (in this order):

- the stream server's port (default:`8081`);
- the stream server's media folder (default: `media`);
- the proxy server's port (default: `8080`);
- the proxy server's host (default: `localhost`);
- the stream server's listening port to the proxy server (default: `8081`)
- the block delay (default: `2000`)
- a parameter that is either `0` (do not experimental output) or `1` (show experimental output) (default: `0`).

This script assumes that its runner is using Linux (Windows Subsystem for Linux included) or MacOS. It is runnable via `./run_secure_streaming.sh` or its derivatives (`sh`, `bash`, etc. instead of `./`). It also assumes that you are running under this exact [project structure](#project-structure), with the extreme importance of `proxycrypto.config` and `servercrypto.config` in the `config` directory and all the cryptographic files under the `crypto` directory under the exact names.

### Distributed Systems (different servers on different machines)

If you prefer the distributed systems approach, you can run, separately, from the source directory:

`go run stream-server/*.go` on one machine

`go run proxy-server/*.go` on the other machine

The command-line arguments are the same as the local version, and they must match (more specifically, the stream server's port and the proxy server's stream listening port).
