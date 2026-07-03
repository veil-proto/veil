package engine

// DefaultTunMTU is the interface MTU every VEIL TUN device is created with.
// It matches maxTransportPlaintext (fragment.go), the protocol's own frame
// ceiling — going higher would just let the OS build packets our own wire
// format can't send in one frame anyway. There is no config knob for this:
// the real adaptation to a path's actual MTU happens per peer, below this
// ceiling, via active probing (pmtu.go) rather than by asking the user to
// guess a static interface MTU.
const DefaultTunMTU = 1418

// tunWriteOffset is the headroom kept in front of every packet handed to
// WriteBatch. Decapsulated packets start tagLen (16) bytes into their UDP read
// buffer, which is also enough for the virtio-net header the Linux TUN write
// path prepends when offloads are enabled.
const tunWriteOffset = 16
