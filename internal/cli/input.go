package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
)

const maxInteractiveLineBytes = 64 << 10

var errInteractiveLineTooLong = errors.New("interactive input line is too long")

// readBoundedLine retains at most one bounded line and drains the remainder of
// an oversized line so the next prompt stays aligned with the next answer.
// The returned text includes a trailing newline, matching bufio.Reader.ReadString.
func readBoundedLine(reader *bufio.Reader) (string, error) {
	return readBoundedLineFragments(func() ([]byte, error) { return reader.ReadSlice('\n') })
}

// Read only bytes already buffered after waiting for the descriptor. A canceled
// prompt must not leave a background reader consuming a later prompt's input.
func readBoundedLineContext(ctx context.Context, input *os.File, reader *bufio.Reader) (string, error) {
	if ctx == nil || input == nil {
		return readBoundedLine(reader)
	}
	return readBoundedLineFragments(func() ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if reader.Buffered() == 0 {
			if err := waitInteractiveInput(ctx, input); err != nil {
				return nil, err
			}
			if _, err := reader.Peek(1); err != nil {
				return nil, err
			}
		}
		buffered, _ := reader.Peek(reader.Buffered())
		if end := bytes.IndexByte(buffered, '\n'); end >= 0 {
			return reader.ReadSlice('\n')
		}
		_, _ = reader.Discard(len(buffered))
		return buffered, bufio.ErrBufferFull
	})
}

func readBoundedLineFragments(next func() ([]byte, error)) (string, error) {
	var line strings.Builder
	tooLong := false
	gotInput := false
	for {
		fragment, err := next()
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
