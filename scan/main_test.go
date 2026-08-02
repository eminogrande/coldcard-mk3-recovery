package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestPBKDF2Equivalence(t *testing.T) {
	pw := []byte("abuse blade mask power depth safe rely hospital resemble comic matrix engine sock come jelly scout want thought net animal panic head proud fiction")
	a := pbkdf2_2048(pw, []byte("mnemonic"))
	b := pbkdf2_2048_go(pw, []byte("mnemonic"))
	if !bytes.Equal(a, b) {
		t.Fatalf("cgo/openssl PBKDF2 != pure-Go PBKDF2")
	}
}

func TestPhysicalFirstBootReferenceVector(t *testing.T) {
	mix := mixerWords(3487)
	entropy, ok := seedEntropy(3547144342, 0, 0, 3191, &mix)
	if !ok {
		t.Fatal("reference candidate failed RNG continuous test")
	}
	want, err := hex.DecodeString("407993c6f9053754e0c25293e963fca27f821257da32426ab4bcc80383b76399")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(entropy[:], want) {
		t.Fatalf("physical-flow reference entropy mismatch: got %x want %x", entropy, want)
	}
	mnemonic := entropyToMnemonic(entropy)
	seed := pbkdf2_2048([]byte(mnemonic), []byte("mnemonic"))
	addresses, _ := candidateAddresses(seed, 1)
	if len(addresses) != 1 || addresses[0] != "bc1qqf80a8pg8mzp5qyzacqv3w7jt595pjf0zzznew" {
		t.Fatalf("physical-flow reference address mismatch: got %v", addresses)
	}
}

func benchSeed64() ([]byte, [32]byte) {
	mix := mixerWords(0)
	ent, _ := seedEntropy(0xDEADBEEF, 0x1234, 0x99, 3, &mix)
	mn := entropyToMnemonic(ent)
	return pbkdf2_2048([]byte(mn), []byte("mnemonic")), ent
}

func BenchmarkEntropyOnly(b *testing.B) {
	mix := mixerWords(0)
	for i := 0; i < b.N; i++ {
		seedEntropy(uint32(i), 0x1234, 0x99, 3, &mix)
	}
}

func BenchmarkMnemonicOnly(b *testing.B) {
	_, ent := benchSeed64()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		entropyToMnemonic(ent)
	}
}

func BenchmarkPBKDF2Only(b *testing.B) {
	_, ent := benchSeed64()
	mn := entropyToMnemonic(ent)
	pw := []byte(mn)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pbkdf2_2048(pw, []byte("mnemonic"))
	}
}

func BenchmarkPubkeyOnly(b *testing.B) {
	seed64, _ := benchSeed64()
	k := seed64[:32]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pubCompressed(k)
	}
}

func BenchmarkFullChain(b *testing.B) {
	mix := mixerWords(0)
	for i := 0; i < b.N; i++ {
		ent, _ := seedEntropy(uint32(i), 0x1234, 0x99, 3, &mix)
		mn := entropyToMnemonic(ent)
		seed64 := pbkdf2_2048([]byte(mn), []byte("mnemonic"))
		candidateAddresses(seed64, 1)
	}
}
