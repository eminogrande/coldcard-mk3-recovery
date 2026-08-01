package main

import (
	"crypto/sha256"
	"encoding/binary"
)

type mixer struct{ pad, n, d, dat uint32 }

func newMixer() *mixer { return &mixer{0x0A8CE26F, 69, 233, 0} }
func (m *mixer) next() uint32 {
	m.pad = m.pad + m.dat + m.d*m.n
	m.pad = (m.pad << 3) | (m.pad >> 29)
	m.n = m.pad | 2
	m.d = m.d ^ ((m.pad << 31) + (m.pad >> 1))
	m.dat = (m.dat ^ (m.pad & 0xFF) ^ (m.d >> 8) ^ 1) & 0xFF
	return m.pad ^ (m.d << 5) ^ (m.pad >> 18) ^ (m.dat << 1)
}

type chip struct{ pad, n, d, dat uint32 }

func newChip(pad32 uint32) *chip { return &chip{pad32, 69, 233, 0} }
func (c *chip) next() uint32 {
	c.pad = c.pad + c.dat + c.d*c.n
	c.pad = (c.pad << 3) | (c.pad >> 29)
	c.n = c.pad | 2
	c.d = c.d ^ ((c.pad << 31) + (c.pad >> 1))
	c.dat = (c.dat ^ (c.pad & 0xFF) ^ (c.d >> 8) ^ 1) & 0xFF
	return c.pad ^ (c.d << 5) ^ (c.pad >> 18) ^ (c.dat << 1)
}

// seedEntropy returns SHA256(raw) for the universal model (rtc TR=69, SSR=233).
// ok=false if the on-device fatal (chip==last) would trigger.
func seedEntropy(pad32 uint32, skip int) (ent [32]byte, ok bool) {
	c := newChip(pad32)
	for i := 0; i < skip; i++ {
		c.next()
	}
	m := newMixer()
	var raw [32]byte
	last := uint32(0)
	for i := 0; i < 8; i++ {
		cv := c.next()
		if i > 0 && cv == last {
			return ent, false
		}
		last = cv
		cv ^= m.next()
		binary.LittleEndian.PutUint32(raw[i*4:], cv)
	}
	return sha256.Sum256(raw[:]), true
}
