package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/ripemd160"
)

var words []string

func entropyToMnemonic(ent [32]byte) string {
	cs := sha256.Sum256(ent[:])
	var sb strings.Builder
	sb.Grow(280)
	getBit := func(i int) uint {
		if i < 256 {
			return uint((ent[i/8] >> (7 - uint(i%8))) & 1)
		}
		return uint((cs[0] >> (7 - uint(i-256))) & 1)
	}
	for w := 0; w < 24; w++ {
		idx := uint(0)
		for b := 0; b < 11; b++ {
			idx = (idx << 1) | getBit(w*11+b)
		}
		if w > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(words[idx])
	}
	return sb.String()
}

type extKey struct{ key, cc []byte }

const H = 0x80000000

func masterKey(seed []byte) extKey {
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	mac.Write(seed)
	I := mac.Sum(nil)
	return extKey{I[:32], I[32:]}
}

func ckdPriv(k extKey, index uint32) extKey {
	mac := hmac.New(sha512.New, k.cc)
	if index >= H {
		mac.Write([]byte{0})
		mac.Write(k.key)
	} else {
		mac.Write(secp256k1.PrivKeyFromBytes(k.key).PubKey().SerializeCompressed())
	}
	var ib [4]byte
	binary.BigEndian.PutUint32(ib[:], index)
	mac.Write(ib[:])
	I := mac.Sum(nil)
	var child secp256k1.ModNScalar
	child.Add(&secp256k1.PrivKeyFromBytes(I[:32]).Key)
	child.Add(&secp256k1.PrivKeyFromBytes(k.key).Key)
	cb := child.Bytes()
	return extKey{cb[:], I[32:]}
}

func hash160(b []byte) []byte {
	s := sha256.Sum256(b)
	r := ripemd160.New()
	r.Write(s[:])
	return r.Sum(nil)
}

var b32c = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func polymod(vals []int) int {
	chk := 1
	gen := [5]int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	for _, v := range vals {
		top := chk >> 25
		chk = ((chk & 0x1ffffff) << 5) ^ v
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func convBits(data []byte, from, to uint, pad bool) []int {
	acc, bits := 0, uint(0)
	ret := []int{}
	maxv := (1 << to) - 1
	for _, b := range data {
		acc = (acc << from) | int(b)
		bits += from
		for bits >= to {
			bits -= to
			ret = append(ret, (acc>>bits)&maxv)
		}
	}
	if pad && bits > 0 {
		ret = append(ret, (acc<<(to-bits))&maxv)
	}
	return ret
}

func p2wpkh(prog []byte) string {
	hrp := "bc"
	data := append([]int{0}, convBits(prog, 8, 5, true)...)
	exp := []int{}
	for i := 0; i < 2; i++ {
		exp = append(exp, int(hrp[i]>>5))
	}
	exp = append(exp, 0)
	for i := 0; i < 2; i++ {
		exp = append(exp, int(hrp[i]&31))
	}
	vals := append(append(exp, data...), 0, 0, 0, 0, 0, 0)
	pm := polymod(vals) ^ 1
	var sb strings.Builder
	sb.WriteString("bc1")
	for _, c := range data {
		sb.WriteByte(b32c[c])
	}
	for i := 0; i < 6; i++ {
		sb.WriteByte(b32c[(pm>>uint(5*(5-i)))&31])
	}
	return sb.String()
}

func addrFromPriv(priv []byte) string {
	pk := secp256k1.PrivKeyFromBytes(priv).PubKey()
	return p2wpkh(hash160(pk.SerializeCompressed()))
}
