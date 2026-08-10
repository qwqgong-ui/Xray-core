//go:build !linux

package buf

import "io"

func NewZeroCopyWriter(writer io.Writer) Writer {
	return NewWriter(writer)
}
