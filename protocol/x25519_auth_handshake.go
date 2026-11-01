package protocol

import (
	"crypto/ed25519"
	"fmt"
	"io"
)

/*
Stream Server: assina as duas chaves públicas X25519 e envia a assinatura.
Proxy: verifica a assinatura do servidor e envia a sua.
Stream Server: verifica a assinatura do Proxy.
alguma assinatura for inválida, o handshake é rejeitado.
*/

// authenticates both participants after exchanging
// X25519 public keys. The server sends its signature first.
func AuthenticateX25519Server(
	reader io.Reader,
	writer io.Writer,
	serverPrivateKey ed25519.PrivateKey,
	trustedProxyPublicKey ed25519.PublicKey,
	serverX25519 []byte,
	proxyX25519 []byte,
) error {
	serverSignature, err := SignX25519Exchange(
		serverPrivateKey, X25519SignerServer, serverX25519, proxyX25519,
	)
	if err != nil {
		return fmt.Errorf("sign server X25519 exchange: %w", err)
	}

	n, err := writer.Write(serverSignature)
	if err != nil {
		return fmt.Errorf("send server signature: %w", err)
	}
	if n != len(serverSignature) {
		return io.ErrShortWrite
	}

	proxySignature := make([]byte, ed25519.SignatureSize)
	if _, err := io.ReadFull(reader, proxySignature); err != nil {
		return fmt.Errorf("receive proxy signature: %w", err)
	}

	if err := VerifyX25519Exchange(
		trustedProxyPublicKey, X25519SignerProxy,
		serverX25519, proxyX25519, proxySignature,
	); err != nil {
		return fmt.Errorf("authenticate proxy: %w", err)
	}
	return nil
}

// AuthenticateX25519Proxy verifies the server signature before sending
// the proxy signature. Both signatures cover the same ephemeral public keys.
func AuthenticateX25519Proxy(
	reader io.Reader,
	writer io.Writer,
	proxyPrivateKey ed25519.PrivateKey,
	trustedServerPublicKey ed25519.PublicKey,
	serverX25519 []byte,
	proxyX25519 []byte,
) error {
	serverSignature := make([]byte, ed25519.SignatureSize)
	if _, err := io.ReadFull(reader, serverSignature); err != nil {
		return fmt.Errorf("receive server signature: %w", err)
	}

	if err := VerifyX25519Exchange(
		trustedServerPublicKey, X25519SignerServer,
		serverX25519, proxyX25519, serverSignature,
	); err != nil {
		return fmt.Errorf("authenticate server: %w", err)
	}

	proxySignature, err := SignX25519Exchange(
		proxyPrivateKey, X25519SignerProxy, serverX25519, proxyX25519,
	)
	if err != nil {
		return fmt.Errorf("sign proxy X25519 exchange: %w", err)
	}
	n, err := writer.Write(proxySignature)
	if err != nil {
		return fmt.Errorf("send proxy signature: %w", err)
	}
	if n != len(proxySignature) {
		return io.ErrShortWrite
	}
	return nil
}
