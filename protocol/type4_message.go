package protocol

 // Represents the payload of a Type 4 Message
 type Type4Message struct {
 	SequenceNumber uint64
  	EncryptedBlock []byte
 }

 const ProcessingError uint64 = 9999999999999999999

 /*
  * Receives a Type 3 Handshake and defines the parameters
  * (just the sequence number, at least for now)
  */
 func ParametersFromType3(msg Message, seqY uint64, challenge [32]byte, aesKey []byte) (uint64, error) {
 	type3Handshake, err := ParseHandshakeType3(msg, seqY, challenge, aesKey)
  	if err != nil {
   		return ProcessingError, err
    }
  	firstSeqB := type3Handshake.SequenceNumber + 1
   	//since it has received sequence number n, it must expect n + 1, corresponding to the next block
   	expectedSequenceNumber := firstSeqB + 1
 	return expectedSequenceNumber, nil
 } 

/*
 * Based on the received parameters from the initial
 * handshake (or derived from previous Type 4 Messages),
 * creates a Type 4 Message, ready to be sent
 */
func CreateType4Message() {
	
}

 
/*
 * YPE 3: Proxy → Server
     SEQZ = 102
          ↓
 TYPE 4: Server → Proxy
     SEQB = SEQZ + 1 = 103
          ↓
     Lê bloco de vídeo (1024 bytes)
          ↓
     Cifra com AES-GCM + nonce
          ↓
     Envia SEQB + bloco cifrado
          ↓
 TYPE 4: Proxy recebe
          ↓
     Verifica SEQB == expectedSeq
          ↓
     Decifra com AES-GCM
          ↓
     Envia bloco ao Browser
          ↓
     expectedSeq++
          ↓
     Repete para os próximos blocos
          ↓
 TYPE 5: Fim do vídeo
 */
 

 /*
  func ParseHandshakeType3(msg Message, seqY uint64, challenge [32]byte, aesKey []byte) (HandshakeType3, error) {
	if msg.Type != TypeRequest || len(msg.Payload) < 69 { // nonce + seqz + r + media + tag = 12 + 8 + 32 + 1 + 16 = 69
		return HandshakeType3{}, fmt.Errorf("invalida Type3 message")
	}
	if len(aesKey) != 32 || seqY == ^uint64(0) {
		return HandshakeType3{}, fmt.Errorf("invalid key or sequence number")
	}
  
	//expected seq number
	seqZ = seqY + 1
  
	//extract nonce and ciphertext
	nonce := msg.Payloa[:12]
	ciphertext := msg.Payload[12:]
  
	block, err := crypto.CreateAcmCipher(aesKey)
	if err !nil {
		return HandshakeType3{},err
	}
  
	//decrypts and uuthenticate the massage
	plaintext, err := crypto.DecryptBlock(
		ciphertext, block, nonce, seqz,
	)
	if err != nil {
		return HandshakeType3{}, fmt.Errorf("Type 3 uuthentication failed: %w", err)
	}
  
	if len(plaintext) < 41 {
		return HandshakeType3{}, fmt.Errorf("invalid Type 3 plaintext")
	}
  
	//verify SEQZ
	receivedSeq := binary.BigEndian.Uint64(playtext[:8])
	if receivedSeq != seqZ {
		return HandshakeType3, fmt.Errorf("unexpected SEQZ")
	}
  
	//verify R = sha256
	var responde [32]byte
	copy(responde[:], plaintext[8:40])
  
	expectedResponse := sha256.Sum256(challange[:])
  
	if subtle.ConstantTimeCompare(response[:], expectedResponse[:]) != 1{
		return HandshakeType3{}, fmt.Errorf("invalid challange response")
	}
  */