// Package canon implements VEIL-CANON-1 deterministic TLV capsules.
package canon

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

const (
	fieldHeaderLen   = 6
	capsuleHeaderLen = 8
)

var (
	ErrDuplicateField = errors.New("canon: duplicate field id")
	ErrFieldOrder     = errors.New("canon: fields not sorted by id")
	ErrTruncated      = errors.New("canon: truncated input")
	ErrTrailingData   = errors.New("canon: trailing data")
)

// Field is one canonical TLV field.
type Field struct {
	ID    uint16
	Value []byte
}

// Capsule is a VEIL-CANON capsule: type, version, field count, then fields.
type Capsule struct {
	Type    uint16
	Version uint16
	Fields  []Field
}

// DecodeOptions lets callers enforce their per-capsule field registry.
type DecodeOptions struct {
	// KnownFields lists fields recognized by the caller. Unknown fields are
	// allowed unless IsCritical marks them critical.
	KnownFields map[uint16]struct{}
	// IsCritical reports whether an unknown field ID must abort parsing.
	IsCritical  func(uint16) bool
	MaxFields   uint32
	MaxValueLen uint32
}

// EncodeFields encodes fields deterministically sorted by ascending field ID.
// Values are copied into the returned wire image.
func EncodeFields(fields []Field) ([]byte, error) {
	sorted := append([]Field(nil), fields...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	for i := 1; i < len(sorted); i++ {
		if sorted[i-1].ID == sorted[i].ID {
			return nil, fmt.Errorf("%w: %d", ErrDuplicateField, sorted[i].ID)
		}
	}

	var total int
	for _, f := range sorted {
		total += fieldHeaderLen + len(f.Value)
	}
	out := make([]byte, 0, total)
	for _, f := range sorted {
		var hdr [fieldHeaderLen]byte
		binary.BigEndian.PutUint16(hdr[0:2], f.ID)
		binary.BigEndian.PutUint32(hdr[2:6], uint32(len(f.Value)))
		out = append(out, hdr[:]...)
		out = append(out, f.Value...)
	}
	return out, nil
}

// EncodeCapsule encodes a complete deterministic capsule.
func EncodeCapsule(c Capsule) ([]byte, error) {
	fields, err := EncodeFields(c.Fields)
	if err != nil {
		return nil, err
	}
	var hdr [capsuleHeaderLen]byte
	binary.BigEndian.PutUint16(hdr[0:2], c.Type)
	binary.BigEndian.PutUint16(hdr[2:4], c.Version)
	binary.BigEndian.PutUint32(hdr[4:8], uint32(len(c.Fields)))
	out := make([]byte, 0, len(hdr)+len(fields))
	out = append(out, hdr[:]...)
	out = append(out, fields...)
	return out, nil
}

// DecodeCapsule decodes and validates a canonical capsule. The input must be a
// complete capsule with fields already sorted by ID.
func DecodeCapsule(in []byte, opts DecodeOptions) (Capsule, error) {
	if len(in) < capsuleHeaderLen {
		return Capsule{}, ErrTruncated
	}
	c := Capsule{
		Type:    binary.BigEndian.Uint16(in[0:2]),
		Version: binary.BigEndian.Uint16(in[2:4]),
	}
	count := binary.BigEndian.Uint32(in[4:8])
	if opts.MaxFields > 0 && count > opts.MaxFields {
		return Capsule{}, fmt.Errorf("canon: field count %d exceeds limit %d", count, opts.MaxFields)
	}
	pos := capsuleHeaderLen
	var prev uint16
	for i := uint32(0); i < count; i++ {
		if len(in)-pos < fieldHeaderLen {
			return Capsule{}, ErrTruncated
		}
		id := binary.BigEndian.Uint16(in[pos : pos+2])
		l := binary.BigEndian.Uint32(in[pos+2 : pos+6])
		pos += fieldHeaderLen
		if opts.MaxValueLen > 0 && l > opts.MaxValueLen {
			return Capsule{}, fmt.Errorf("canon: field %d length %d exceeds limit %d", id, l, opts.MaxValueLen)
		}
		if uint64(len(in)-pos) < uint64(l) {
			return Capsule{}, ErrTruncated
		}
		if i > 0 {
			if id == prev {
				return Capsule{}, fmt.Errorf("%w: %d", ErrDuplicateField, id)
			}
			if id < prev {
				return Capsule{}, fmt.Errorf("%w: %d after %d", ErrFieldOrder, id, prev)
			}
		}
		if _, ok := opts.KnownFields[id]; !ok && opts.IsCritical != nil && opts.IsCritical(id) {
			return Capsule{}, fmt.Errorf("canon: unknown critical field %d", id)
		}
		value := make([]byte, int(l))
		copy(value, in[pos:pos+int(l)])
		c.Fields = append(c.Fields, Field{ID: id, Value: value})
		pos += int(l)
		prev = id
	}
	if pos != len(in) {
		return Capsule{}, ErrTrailingData
	}
	return c, nil
}
