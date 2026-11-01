package main

import (
	"bufio"
	"errors"
	"io"
	"strings"
)

// readLine reads exactly one HTTP header line while preserving subsequent
// buffered bytes for body streaming using the same reader.
func readLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
		return "", err
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), nil
}
