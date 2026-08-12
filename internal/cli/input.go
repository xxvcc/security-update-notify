package cli

import (
	"bufio"
	"errors"
	"io"
	"strings"
)

const maxInteractiveLineBytes = 64 << 10

var errInteractiveLineTooLong = errors.New("interactive input line is too long")

// readBoundedLine retains at most one bounded line and drains the remainder of
// an oversized line so the next prompt stays aligned with the next answer.
// The returned text includes a trailing newline, matching bufio.Reader.ReadString.
func readBoundedLine(reader *bufio.Reader) (string, error) {
	var line strings.Builder
	tooLong := false
	gotInput := false
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(fragment) > 0 {
			gotInput = true
			hasNewline := fragment[len(fragment)-1] == '\n'
			payload := fragment
			if hasNewline {
				payload = fragment[:len(fragment)-1]
			}
			if !tooLong {
				remaining := maxInteractiveLineBytes - line.Len()
				if len(payload) > remaining {
					tooLong = true
				} else {
					line.Write(payload)
					if hasNewline {
						line.WriteByte('\n')
					}
				}
			}
		}

		switch {
		case err == nil:
			if tooLong {
				return "", errInteractiveLineTooLong
			}
			return line.String(), nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			if !gotInput {
				return "", io.EOF
			}
			if tooLong {
				return "", errInteractiveLineTooLong
			}
			return line.String(), io.EOF
		default:
			return "", err
		}
	}
}
