package smtpd

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
)

// TestReadLine covers the reader that took the place of a bufio.Scanner. The
// session reads its command lines and the chunks of BDAT from one reader, so
// a line must leave the octets that follow it where they are.
func TestReadLine(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		want  []string
		rest  string
		final error
	}{
		{
			name:  "two lines",
			in:    "EHLO one\r\nNOOP\r\n",
			want:  []string{"EHLO one", "NOOP"},
			final: io.EOF,
		},
		{
			name:  "a line feed without a carriage return",
			in:    "EHLO one\nNOOP\n",
			want:  []string{"EHLO one", "NOOP"},
			final: io.EOF,
		},
		{
			name:  "an empty line",
			in:    "\r\nNOOP\r\n",
			want:  []string{"", "NOOP"},
			final: io.EOF,
		},
		{
			name:  "a last line without a line break",
			in:    "EHLO one\r\nQUIT",
			want:  []string{"EHLO one", "QUIT"},
			final: io.EOF,
		},
		{
			name: "the octets after the line stay where they are",
			in:   "BDAT 5\r\nhelloNOOP\r\n",
			want: []string{"BDAT 5"},
			rest: "helloNOOP\r\n",
		},
		{
			// The line break counts toward the bound, so the longest line
			// that gets through is two octets shorter than it.
			name:  "a line of the greatest length",
			in:    strings.Repeat("b", maxLineLength-2) + "\r\n",
			want:  []string{strings.Repeat("b", maxLineLength-2)},
			final: io.EOF,
		},
		{
			name:  "a line that is too long",
			in:    strings.Repeat("b", maxLineLength) + "\r\n",
			final: bufio.ErrTooLong,
		},
		{
			name:  "a line without an end",
			in:    strings.Repeat("b", 10),
			want:  []string{strings.Repeat("b", 10)},
			final: io.EOF,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := &session{reader: bufio.NewReader(strings.NewReader(test.in))}

			for i, want := range test.want {
				got, err := s.readLine()
				if err != nil {
					t.Fatalf("line %d: readLine() gave the error %v", i, err)
				}
				if got != want {
					t.Fatalf("line %d: readLine() = %q, want %q", i, got, want)
				}
			}

			if test.rest != "" {
				rest, err := io.ReadAll(s.reader)
				if err != nil {
					t.Fatalf("read the rest: %v", err)
				}
				if string(rest) != test.rest {
					t.Errorf("the reader holds %q, want %q", rest, test.rest)
				}
				return
			}

			if _, err := s.readLine(); !errors.Is(err, test.final) {
				t.Errorf("the last readLine() gave %v, want %v", err, test.final)
			}
		})
	}
}
