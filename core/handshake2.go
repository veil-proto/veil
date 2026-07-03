package core

import (
	"encoding/binary"
	"errors"
)

type Msg2SessionParams struct {
	TagLen                 byte
	TagWindowLog2          byte
	ReplayWindowLog2       byte
	PaddingProfile         byte
	InnerMTU               uint16
	KeepaliveSeconds       uint16
	RekeyAfterTime         uint32
	RejectAfterTime        uint32
	RekeyAfterPacketsLog2  byte
	SessionNonceSeed       [32]byte
	ResponderNonce         [16]byte
	Reserved               [31]byte
}

func (m *Msg2SessionParams) Encode() []byte {
	out := make([]byte, 96)
	out[0] = m.TagLen
	out[1] = m.TagWindowLog2
	out[2] = m.ReplayWindowLog2
	out[3] = m.PaddingProfile
	binary.LittleEndian.PutUint16(out[4:6], m.InnerMTU)
	binary.LittleEndian.PutUint16(out[6:8], m.KeepaliveSeconds)
	binary.LittleEndian.PutUint32(out[8:12], m.RekeyAfterTime)
	binary.LittleEndian.PutUint32(out[12:16], m.RejectAfterTime)
	out[16] = m.RekeyAfterPacketsLog2
	copy(out[17:49], m.SessionNonceSeed[:])
	copy(out[49:65], m.ResponderNonce[:])
	copy(out[65:96], m.Reserved[:])
	return out
}

func DecodeMsg2SessionParams(data []byte) (*Msg2SessionParams, error) {
	if len(data) != 96 {
		return nil, errors.New("invalid Msg2SessionParams size")
	}
	var m Msg2SessionParams
	m.TagLen = data[0]
	m.TagWindowLog2 = data[1]
	m.ReplayWindowLog2 = data[2]
	m.PaddingProfile = data[3]
	m.InnerMTU = binary.LittleEndian.Uint16(data[4:6])
	m.KeepaliveSeconds = binary.LittleEndian.Uint16(data[6:8])
	m.RekeyAfterTime = binary.LittleEndian.Uint32(data[8:12])
	m.RejectAfterTime = binary.LittleEndian.Uint32(data[12:16])
	m.RekeyAfterPacketsLog2 = data[16]
	copy(m.SessionNonceSeed[:], data[17:49])
	copy(m.ResponderNonce[:], data[49:65])
	copy(m.Reserved[:], data[65:96])
	return &m, nil
}
