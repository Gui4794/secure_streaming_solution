package config

import (
	"os"
	"testing"
)

func TestParseConfigFile(t *testing.T) {
	// Move to project root because config paths
	// are relative to that directory.
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Chdir(".."); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(originalDir)

	for _, component := range []string{"proxy", "server"} {
		cfg, err := ParseConfigFile(component)
		if err != nil {
			t.Fatal(err)
		}

		if cfg.CipherAlgorithm != "AES" {
			t.Fatal("Incorrect cipher algorithm")
		}

		if cfg.CipherMode != "GCM" {
			t.Fatal("Incorrect cipher mode")
		}

		if cfg.IVSize != 96 {
			t.Fatal("Incorrect IV size")
		}

		if cfg.SymKeySize != 256 {
			t.Fatal("Incorrect key size")
		}

		t.Logf("%s configuration loaded successfully", component)
	}
}
