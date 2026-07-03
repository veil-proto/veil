package engine

import "encoding/binary"

const tcpTimestampOptionLen = 12

func tcpMSSClamp(budget int) uint16 {
	// Keep common IPv4 TCP data packets within a single VEIL transport frame,
	// sized to the peer's current (probed) frame budget rather than the
	// protocol ceiling, so TCP never generates segments that would fall into
	// a path MTU black hole.
	mss := budget - 20 - 20 - tcpTimestampOptionLen
	if mss < 536 {
		return 536
	}
	return uint16(mss)
}

func clampTCPMSS(packet []byte, budget int) bool {
	if len(packet) < 40 || packet[0]>>4 != 4 {
		return false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl+20 || packet[9] != 6 {
		return false
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < ihl+20 || totalLen > len(packet) {
		return false
	}

	tcp := packet[ihl:totalLen]
	tcpHeaderLen := int(tcp[12]>>4) * 4
	if tcpHeaderLen < 20 || tcpHeaderLen > len(tcp) {
		return false
	}
	if tcp[13]&0x02 == 0 { // SYN
		return false
	}

	limit := tcpMSSClamp(budget)
	changed := false
	for i := 20; i < tcpHeaderLen; {
		kind := tcp[i]
		switch kind {
		case 0:
			i = tcpHeaderLen
		case 1:
			i++
		default:
			if i+1 >= tcpHeaderLen {
				return false
			}
			optLen := int(tcp[i+1])
			if optLen < 2 || i+optLen > tcpHeaderLen {
				return false
			}
			if kind == 2 && optLen == 4 {
				cur := binary.BigEndian.Uint16(tcp[i+2 : i+4])
				if cur > limit {
					binary.BigEndian.PutUint16(tcp[i+2:i+4], limit)
					changed = true
				}
				i = tcpHeaderLen
			} else {
				i += optLen
			}
		}
	}
	if !changed {
		return false
	}

	rewriteTCPChecksum(packet, ihl, totalLen)
	return true
}

func rewriteTCPChecksum(packet []byte, ihl, totalLen int) {
	tcp := packet[ihl:totalLen]
	tcp[16], tcp[17] = 0, 0

	sum := checksumAdd(packet[12:16], 0)
	sum = checksumAdd(packet[16:20], sum)
	var pseudo [4]byte
	pseudo[1] = 6
	binary.BigEndian.PutUint16(pseudo[2:4], uint16(totalLen-ihl))
	sum = checksumAdd(pseudo[:], sum)
	sum = checksumAdd(tcp, sum)
	binary.BigEndian.PutUint16(tcp[16:18], checksumFold(sum))
}

func checksumAdd(b []byte, sum uint32) uint32 {
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

func checksumFold(sum uint32) uint16 {
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
