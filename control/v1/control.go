// Package controlv1 implements encrypted control-frame payload encoding for
// VEIL-CONTROL-1. The records themselves are carried inside record/v1 CONTROL
// frames; this package owns the canonical control capsule.
package controlv1

import "github.com/veil-proto/veil/canon"

type Type uint16

const Version uint16 = 1

const (
	ControlRekeyPrepare     Type = 1
	ControlRekeyCommit      Type = 2
	ControlPQOffer          Type = 3
	ControlPQAnswer         Type = 4
	ControlPQConfirm        Type = 5
	ControlPQRefreshOffer   Type = 6
	ControlPQRefreshAnswer  Type = 7
	ControlPQRefreshConfirm Type = 8
	ControlPathChallenge    Type = 9
	ControlPathResponse     Type = 10
	ControlPMTUProbe        Type = 11
	ControlPMTUAck          Type = 12
	ControlClose            Type = 13
	ControlStatsOptional    Type = 14
)

type Frame struct {
	Type   Type
	Fields []canon.Field
}

func Marshal(f Frame) ([]byte, error) {
	return canon.EncodeCapsule(canon.Capsule{Type: uint16(f.Type), Version: Version, Fields: f.Fields})
}

func Parse(in []byte, opts canon.DecodeOptions) (Frame, error) {
	c, err := canon.DecodeCapsule(in, opts)
	if err != nil {
		return Frame{}, err
	}
	return Frame{Type: Type(c.Type), Fields: c.Fields}, nil
}
