package config

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"
)

const (
	StreamServer = "server"
	ProxyServer  = "proxy"

	/*
	 * The paths for the config files (starting from the project_1 directory)
	 * Please change if needed
	 */
	ServerConfigFileName = "./config/servercrypto.config"
	ProxyConfigFileName  = "./config/proxycrypto.config"
)

/*
* ConfigOutput is a helper struct that represents the output
* of a config (*.config) file. Note that it assumes
* a file is exactly how it is in the handout
 */

type ConfigOutput struct {
	CipherAlgorithm string `xml:"SymCipherSuite>Algorithm"`
	CipherMode      string `xml:"SymCipherSuite>Mode"`
	IV              string `xml:"SymCipherSuite>InitializationVector>IV"`
	IVSize          int    `xml:"SymCipherSuite>InitializationVector>IVSize"`
	Padding         string `xml:"SymCipherSuite>Padding"`
	MacAlgorithm    string `xml:"MACSuite>Algorithm"`
	SymKey          string `xml:"ConfiguredKeys>SymmetricKey>SKey"`
	SymKeySize      int    `xml:"ConfiguredKeys>SymmetricKey>Keysize"`
	MacKey          string `xml:"ConfiguredKeys>MACKey>MacKey"`
	MacKeySize      string `xml:"ConfiguredKeys>MACKey>MacKeySize"`
}

/*
* ParseConfigFile reads a configuration file and returns a struct
* with its contents, to be processed by the Stream and Proxy servers
 */
func ParseConfigFile(serverName string) (ConfigOutput, error) {
	var fileToOpen string
	switch strings.ToLower(serverName) {
	case StreamServer:
		fileToOpen = ServerConfigFileName
	case ProxyServer:
		fileToOpen = ProxyConfigFileName
	}
	xmlContents, err := os.ReadFile(fileToOpen)
	if err != nil {
		return ConfigOutput{}, err
	}
	var configOutput ConfigOutput
	err = xml.Unmarshal(xmlContents, &configOutput)
	if err != nil {
		return ConfigOutput{}, err
	}
	return configOutput, nil
}

// for now : Proxy e o Server só aceitam a configuração AES-256-GCM que implementamos
func (c ConfigOutput) Validate() error {
	if c.CipherAlgorithm != "AES" || c.CipherMode != "GCM" {
		return fmt.Errorf("unsupported cipher suite: %s/%s",
			c.CipherAlgorithm, c.CipherMode)
	}

	if c.IVSize != 96 {
		return fmt.Errorf("invalid IV size: %d", c.IVSize)
	}

	if c.SymKeySize != 128 && c.SymKeySize != 192 && c.SymKeySize != 256 {
		return fmt.Errorf("invalid key size: %d", c.SymKeySize)
	}

	if c.Padding != "NULL" || c.MacAlgorithm != "NULL" {
		return fmt.Errorf("invalid AES-GCM configuration")
	}

	return nil
}
