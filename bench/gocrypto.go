package main

import (
	"crypto/cipher"
	"fmt"
	"hash"
	"time"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/salsa20"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/tea"
	"golang.org/x/crypto/twofish"
	"golang.org/x/crypto/xtea"
)

const iterations = 1_000_000

// Sinks keep the benchmark operations observable to the compiler.
var (
	hashSink   []byte
	blockSink  cipher.Block
	streamSink any
)

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
	fmt.Printf("%-10s hash:    %s\n", name, formatPerOp(time.Since(start)))
}

type blockBenchmark struct {
	newCipher func([]byte) (cipher.Block, error)
}

// benchmarkBlock measures init, encrypt, and decrypt independently. Encryption
// and decryption use the same buffer for source and destination, as in the
// requested encrypt(ctx, text, text) / decrypt(ctx, text, text) pseudocode.
func benchmarkBlock(name string, key, text []byte, bench blockBenchmark) {
	start := time.Now()
	for i := 0; i < iterations; i++ {
		ctx, err := bench.newCipher(key)
		if err != nil {
			panic(fmt.Sprintf("%s init: %v", name, err))
		}
		blockSink = ctx
	}
	initElapsed := time.Since(start)

	ctx, err := bench.newCipher(key)
	if err != nil {
		panic(fmt.Sprintf("%s init: %v", name, err))
	}

	start = time.Now()
	for i := 0; i < iterations; i++ {
		ctx.Encrypt(text, text)
	}
	encryptElapsed := time.Since(start)

	start = time.Now()
	for i := 0; i < iterations; i++ {
		ctx.Decrypt(text, text)
	}
	decryptElapsed := time.Since(start)
	hashSink = text

	fmt.Printf("%-10s init: %s, encrypt: %s, decrypt: %s\n",
		name, formatPerOp(initElapsed), formatPerOp(encryptElapsed), formatPerOp(decryptElapsed))
}

type streamBenchmark[T any] struct {
	init func([]byte, []byte) (T, error)
	xor  func(T, []byte)
}

// benchmarkStream measures init(ctx, key, nonce) and xor(ctx, text, text)
// independently. The XOR operation is in-place.
func benchmarkStream[T any](name string, key, nonce, text []byte, bench streamBenchmark[T]) {
	start := time.Now()
	for i := 0; i < iterations; i++ {
		ctx, err := bench.init(key, nonce)
		if err != nil {
			panic(fmt.Sprintf("%s init: %v", name, err))
		}
		streamSink = ctx
	}
	initElapsed := time.Since(start)

	ctx, err := bench.init(key, nonce)
	if err != nil {
		panic(fmt.Sprintf("%s init: %v", name, err))
	}
	start = time.Now()
	for i := 0; i < iterations; i++ {
		bench.xor(ctx, text)
	}
	xorElapsed := time.Since(start)
	hashSink = text

	fmt.Printf("%-10s init: %s, xor: %s\n", name, formatPerOp(initElapsed), formatPerOp(xorElapsed))
}

type salsaContext struct {
	key   [32]byte
	nonce [8]byte
}

func main() {
	key := []byte("0123456789abcdef0123456789abcdef")
	nonce := []byte("12345678")
	hashInput := []byte("hello world")
	block8 := make([]byte, 8)
	block16 := make([]byte, 16)
	streamText := make([]byte, 64)

	benchmarkHash("blake2b", func() hash.Hash { h, _ := blake2b.New256(nil); return h }, hashInput)
	benchmarkHash("blake2s", func() hash.Hash { h, _ := blake2s.New256(nil); return h }, hashInput)
	benchmarkHash("md4", md4.New, hashInput)
	benchmarkHash("ripemd160", ripemd160.New, hashInput)
	benchmarkHash("sha3-256", sha3.New256, hashInput)

	benchmarkBlock("blowfish", key[:16], block8, blockBenchmark{
		newCipher: func(key []byte) (cipher.Block, error) { return blowfish.NewCipher(key) },
	})
	benchmarkBlock("cast5", key[:16], block8, blockBenchmark{
		newCipher: func(key []byte) (cipher.Block, error) { return cast5.NewCipher(key) },
	})
	benchmarkBlock("tea", key[:16], block8, blockBenchmark{tea.NewCipher})
	benchmarkBlock("xtea", key[:16], block8, blockBenchmark{
		newCipher: func(key []byte) (cipher.Block, error) { return xtea.NewCipher(key) },
	})
	benchmarkBlock("twofish", key, block16, blockBenchmark{
		newCipher: func(key []byte) (cipher.Block, error) { return twofish.NewCipher(key) },
	})

	benchmarkStream("chacha20", key, nonce, streamText, streamBenchmark[*chacha20.Cipher]{
		init: chacha20.NewUnauthenticatedCipher,
		xor:  func(ctx *chacha20.Cipher, text []byte) { ctx.XORKeyStream(text, text) },
	})
	benchmarkStream("salsa20", key, nonce, streamText, streamBenchmark[salsaContext]{
		init: func(key, nonce []byte) (salsaContext, error) {
			var ctx salsaContext
			copy(ctx.key[:], key)
			copy(ctx.nonce[:], nonce)
			return ctx, nil
		},
		xor: func(ctx salsaContext, text []byte) {
			salsa20.XORKeyStream(text, text, ctx.nonce[:], &ctx.key)
		},
	})
}
