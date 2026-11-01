package protocol

import "io"

// sends a Type 255 error-alert message
func SendErrorAlert(w io.Writer, reason string) error {
	return WriteMessage(w, TypeError, []byte(reason))
}
