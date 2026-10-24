package main

import (
	"fmt"
	"hash"
	"time"

	"github.com/deatil/go-hash/ascon"
	"github.com/deatil/go-hash/bash"
	"github.com/deatil/go-hash/belt"
	"github.com/deatil/go-hash/blake256"
	"github.com/deatil/go-hash/blake3"
	"github.com/deatil/go-hash/blake512"
	"github.com/deatil/go-hash/bmw"
	"github.com/deatil/go-hash/cubehash"
	"github.com/deatil/go-hash/echo"
	"github.com/deatil/go-hash/esch"
	"github.com/deatil/go-hash/fugue"
	"github.com/deatil/go-hash/gost/gost34112012256"
	"github.com/deatil/go-hash/gost/gost34112012512"
	"github.com/deatil/go-hash/groestl"
	"github.com/deatil/go-hash/hamsi"
	"github.com/deatil/go-hash/has160"
	"github.com/deatil/go-hash/haval"
	"github.com/deatil/go-hash/jh"
	"github.com/deatil/go-hash/jh2"
	"github.com/deatil/go-hash/k12"
	"github.com/deatil/go-hash/kupyna"
	"github.com/deatil/go-hash/lsh256"
	"github.com/deatil/go-hash/lsh512"
	"github.com/deatil/go-hash/luffa"
	"github.com/deatil/go-hash/md2"
	"github.com/deatil/go-hash/md6"
	"github.com/deatil/go-hash/murmur3"
	"github.com/deatil/go-hash/panama"
	"github.com/deatil/go-hash/radio_gatun"
	"github.com/deatil/go-hash/ripemd"
	"github.com/deatil/go-hash/sha0"
	"github.com/deatil/go-hash/shabal"
	"github.com/deatil/go-hash/shavite"
	"github.com/deatil/go-hash/simd"
	"github.com/deatil/go-hash/skein"
	"github.com/deatil/go-hash/skein512"
	"github.com/deatil/go-hash/skeins"
	"github.com/deatil/go-hash/sm3"
	"github.com/deatil/go-hash/streebog"
	"github.com/deatil/go-hash/tiger"
	"github.com/deatil/go-hash/whirlpool"
	"github.com/deatil/go-hash/xxhash/xxh3"
)

const iterations = 1_000_000

var hashSink []byte

func formatPerOp(d time.Duration) string {
	ns := float64(d.Nanoseconds()) / iterations
	if ns >= 1_000 {
		return fmt.Sprintf("%.3f us/op", ns/1_000)
	}
	return fmt.Sprintf("%.1f ns/op", ns)
}

// benchmarkHash measures: init(ctx); input(ctx, a); a = final(ctx).
func benchmarkHash(name string, newHash func() hash.Hash, input []byte) {
	output := make([]byte, 0, newHash().Size())
	start := time.Now()
	for i := 0; i < iterations; i++ {
		ctx := newHash()
		_, _ = ctx.Write(input)
		output = ctx.Sum(output[:0])
	}
	hashSink = output
	fmt.Printf("%-18s %s\n", name, formatPerOp(time.Since(start)))
}

func main() {
	input := []byte("hello world")
	benchmarks := []struct {
		name string
		new  func() hash.Hash
	}{
		{"ascon-hash", func() hash.Hash { return ascon.NewHash() }},
		{"bash-256", bash.New256},
		{"belt-hash", belt.New},
		{"blake-256", blake256.New},
		{"blake-512", blake512.New},
		{"blake3-256", blake3.New},
		{"bmw-256", bmw.New256},
		{"cubehash-256", cubehash.NewHS256},
		{"echo-256", echo.New256},
		{"esch-256", esch.New256},
		{"fugue-256", fugue.New256},
		{"gost-2012-256", gost34112012256.New},
		{"gost-2012-512", gost34112012512.New},
		{"groestl-256", groestl.New256},
		{"hamsi-256", hamsi.New256},
		{"has-160", has160.New},
		{"haval-256-5", haval.New256_5},
		{"jh", jh.New},
		{"jh2-256", jh2.New256},
		{"kangaroo-twelve", func() hash.Hash { return k12.New(nil) }},
		{"kupyna-256", kupyna.New256},
		{"lsh-256", lsh256.New},
		{"lsh-512", lsh512.New},
		{"luffa-256", luffa.New256},
		{"md2", md2.New},
		{"md6-256", md6.New256},
		{"murmur3-128", func() hash.Hash { return murmur3.New128() }},
		{"panama", panama.New},
		{"radio-gatun-64", radio_gatun.New64},
		{"ripemd-160", ripemd.New160},
		{"sha0", sha0.New},
		{"shabal-256", shabal.New256},
		{"shavite-256", shavite.New256},
		{"simd-256", simd.New256},
		{"skein-512", func() hash.Hash { return skein.New512(nil) }},
		{"skein512-512", skein512.NewHash512},
		{"skeins-512", skeins.New512},
		{"sm3", sm3.New},
		{"streebog-256", streebog.New256},
		{"tiger", tiger.New},
		{"whirlpool", whirlpool.New},
		{"xxh3-64", func() hash.Hash { return xxh3.New64() }},
	}

	for _, benchmark := range benchmarks {
		benchmarkHash(benchmark.name, benchmark.new, input)
	}
}
