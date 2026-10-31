package config

import (
	"encoding/xml"
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
	CipherAlgorithm string `xml: "SymCipherSuite>Algorithm"`
	CipherMode      string `xml: "SymCipherSuite>Mode"`
	IV              string `xml: "SymCipherSuite>InitializationVector>IV`
	IVSize          int    `xml: "SymCipherSuite>InitializationVector>IVSize"`
	Padding         string `xml: "SumCipherSuite>Padding"`
	MacAlgorithm    string `xml: "MACSuite>Algorithm"`
	SymKey          []byte `xml: "ConfiguredKeys>SymmetricKey>SKey"`
	SymKeySize      int    `xml: "ConfiguredKeys>SymmetricKey>Keysize"`
	MacKey          []byte `xml: "MACKey>MacKey"`
	MacKeySize      int    `xml: "MACKey>MacKeySize"`
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
		panic(err)
	}
	var configOutput ConfigOutput
	err = xml.Unmarshal(xmlContents, &configOutput)
	if err != nil {
		panic(err)
	}
	return configOutput, nil
}
