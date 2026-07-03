// Package recordv1 implements VEIL-RECORD-1.
package recordv1

import (
	"encoding/binary"
	"errors"
)

type FrameType byte

const (
	FrameDataIP4       FrameType = 0x01
	FrameDataIP6       FrameType = 0x02
	FrameControl       FrameType = 0x03
	FramePadOnly       FrameType = 0x04
	FrameInnerFragment FrameType = 0x05
)

type Frame struct {
	Type    FrameType
	Flags   byte
	Body    []byte
	Padding []byte
}

var ErrMalformedFrame = errors.New("recordv1: malformed inner frame")

func MarshalFrame(f Frame) ([]byte, error) {
	if len(f.Body) > 0xffff || len(f.Padding) > 0xffff {
		return nil, ErrMalformedFrame
	}
	out := make([]byte, 4+len(f.Body)+len(f.Padding)+2)
	out[0] = byte(f.Type)
	out[1] = f.Flags
	binary.BigEndian.PutUint16(out[2:4], uint16(len(f.Body)))
	copy(out[4:], f.Body)
	copy(out[4+len(f.Body):], f.Padding)
	binary.BigEndian.PutUint16(out[len(out)-2:], uint16(len(f.Padding)))
	return out, nil
}

func ParseFrame(in []byte) (Frame, error) {
	if len(in) < 6 {
		return Frame{}, ErrMalformedFrame
	}
	bodyLen := int(binary.BigEndian.Uint16(in[2:4]))
	padLen := int(binary.BigEndian.Uint16(in[len(in)-2:]))
	bodyEnd := 4 + bodyLen
	if bodyEnd > len(in)-2 || bodyEnd+padLen+2 != len(in) {
		return Frame{}, ErrMalformedFrame
	}
	return Frame{
		Type:    FrameType(in[0]),
		Flags:   in[1],
		Body:    append([]byte(nil), in[4:bodyEnd]...),
		Padding: append([]byte(nil), in[bodyEnd:bodyEnd+padLen]...),
	}, nil
}
