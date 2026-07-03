package controlv1

import (
	"bytes"
	"testing"

	"github.com/veil-proto/veil/canon"
)

func TestControlMarshalParse(t *testing.T) {
	wire, err := Marshal(Frame{
		Type: ControlPathChallenge,
		Fields: []canon.Field{
			{ID: 2, Value: []byte("path")},
			{ID: 1, Value: []byte{1}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(wire, canon.DecodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != ControlPathChallenge || len(got.Fields) != 2 || got.Fields[0].ID != 1 || !bytes.Equal(got.Fields[1].Value, []byte("path")) {
		t.Fatalf("control frame = %+v", got)
	}
}
