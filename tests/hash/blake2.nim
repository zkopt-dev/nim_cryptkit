import "../../src/nim_cryptkit/hash/blake2"
import ../../src/nim_cryptkit/utils/digits
import std/[monotimes, times]

var s: seq[uint8] = charToBin("Hello, World!")

# ============================================================
# BLAKE2s Tests
# ============================================================

echo "--- Test : BLAKE2s-128 ---"
var s128Ctx: Blake2s_128Ctx
blake2s_128Init(s128Ctx)
blake2s_128Input(s128Ctx, s)
let hashS128 = binToHex(blake2s_128Final(s128Ctx))
echo "BLAKE2S-128 Stream   : ", hashS128
echo "BLAKE2S-128 Standard : CB5F50CCA5F56F28B7D885C345FF65DE"
doAssert hashS128 == "CB5F50CCA5F56F28B7D885C345FF65DE", "BLAKE2s-128 Hash Wrong!"
echo ""

echo "--- Test : BLAKE2s-160 ---"
var s160Ctx: Blake2s_160Ctx
blake2s_160Init(s160Ctx)
blake2s_160Input(s160Ctx, s)
let hashS160 = binToHex(blake2s_160Final(s160Ctx))
echo "BLAKE2S-160 Stream   : ", hashS160
echo "BLAKE2S-160 Standard : 5561E2F4CA2C61CF7C2261088DB8342659D2BC98"
doAssert hashS160 == "5561E2F4CA2C61CF7C2261088DB8342659D2BC98", "BLAKE2s-160 Hash Wrong!"
echo ""

echo "--- Test : BLAKE2s-224 ---"
var s224Ctx: Blake2s_224Ctx
blake2s_224Init(s224Ctx)
blake2s_224Input(s224Ctx, s)
let hashS224 = binToHex(blake2s_224Final(s224Ctx))
echo "BLAKE2S-224 Stream   : ", hashS224
echo ""

echo "--- Test : BLAKE2s-256 ---"
var s256Ctx: Blake2s_256Ctx
blake2s_256Init(s256Ctx)
blake2s_256Input(s256Ctx, s)
let hashS256 = binToHex(blake2s_256Final(s256Ctx))
echo "BLAKE2S-256 Stream   : ", hashS256
echo "BLAKE2S-256 Standard : EC9DB904D636EF61F1421B2BA47112A4FA6B8964FD4A0A514834455C21DF7812"
doAssert hashS256 == "EC9DB904D636EF61F1421B2BA47112A4FA6B8964FD4A0A514834455C21DF7812", "BLAKE2s-256 Hash Wrong!"
echo ""


# ============================================================
# BLAKE2b Tests
# ============================================================

echo "--- Test : BLAKE2b-128 ---"
var b128Ctx: Blake2b_128Ctx
blake2b_128Init(b128Ctx)
blake2b_128Input(b128Ctx, s)
let hashB128 = binToHex(blake2b_128Final(b128Ctx))
echo "BLAKE2B-128 Stream   : ", hashB128
echo "BLAKE2B-128 Standard : 3895C59E4AEB0903396B5BE3FBEC69FE"
doAssert hashB128 == "3895C59E4AEB0903396B5BE3FBEC69FE", "BLAKE2b-128 Hash Wrong!"
echo ""

echo "--- Test : BLAKE2b-160 ---"
var b160Ctx: Blake2b_160Ctx
blake2b_160Init(b160Ctx)
blake2b_160Input(b160Ctx, s)
let hashB160 = binToHex(blake2b_160Final(b160Ctx))
echo "BLAKE2B-160 Stream   : ", hashB160
echo "BLAKE2B-160 Standard : 522F974C6500EB7923C28E3B129B52A79405F0FA"
doAssert hashB160 == "522F974C6500EB7923C28E3B129B52A79405F0FA", "BLAKE2b-160 Hash Wrong!"
echo ""

echo "--- Test : BLAKE2b-224 ---"
var b224Ctx: Blake2b_224Ctx
blake2b_224Init(b224Ctx)
blake2b_224Input(b224Ctx, s)
let hashB224 = binToHex(blake2b_224Final(b224Ctx))
echo "BLAKE2B-224 Stream   : ", hashB224
echo ""

echo "--- Test : BLAKE2b-256 ---"
var b256Ctx: Blake2b_256Ctx
blake2b_256Init(b256Ctx)
blake2b_256Input(b256Ctx, s)
let hashB256 = binToHex(blake2b_256Final(b256Ctx))
echo "BLAKE2B-256 Stream   : ", hashB256
echo "BLAKE2B-256 Standard : 511BC81DDE11180838C562C82BB35F3223F46061EBDE4A955C27B3F489CF1E03"
doAssert hashB256 == "511BC81DDE11180838C562C82BB35F3223F46061EBDE4A955C27B3F489CF1E03", "BLAKE2b-256 Hash Wrong!"
echo ""

echo "--- Test : BLAKE2b-384 ---"
var b384Ctx: Blake2b_384Ctx
blake2b_384Init(b384Ctx)
blake2b_384Input(b384Ctx, s)
let hashB384 = binToHex(blake2b_384Final(b384Ctx))
echo "BLAKE2B-384 Stream   : ", hashB384
echo "BLAKE2B-384 Standard : ABCFF1BA93147176D032D840372864602CCC2499E084C0A9F6C459D5BF9220C56F79B02382104B3126D20168C1FC4D31"
doAssert hashB384 == "ABCFF1BA93147176D032D840372864602CCC2499E084C0A9F6C459D5BF9220C56F79B02382104B3126D20168C1FC4D31", "BLAKE2b-384 Hash Wrong!"
echo ""

echo "--- Test : BLAKE2b-512 ---"
var b512Ctx: Blake2b_512Ctx
blake2b_512Init(b512Ctx)
blake2b_512Input(b512Ctx, s)
let hashB512 = binToHex(blake2b_512Final(b512Ctx))
echo "BLAKE2B-512 Stream   : ", hashB512
echo "BLAKE2B-512 Standard : 7DFDB888AF71EAE0E6A6B751E8E3413D767EF4FA52A7993DAA9EF097F7AA3D949199C113CAA37C94F80CF3B22F7D9D6E4F5DEF4FF927830CFFE4857C34BE3D89"
doAssert hashB512 == "7DFDB888AF71EAE0E6A6B751E8E3413D767EF4FA52A7993DAA9EF097F7AA3D949199C113CAA37C94F80CF3B22F7D9D6E4F5DEF4FF927830CFFE4857C34BE3D89", "BLAKE2b-512 Hash Wrong!"
echo ""

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

var
  res128: array[16, uint8]
  res160: array[20, uint8]
  res224: array[28, uint8]
  res256: array[32, uint8]
  res384: array[48, uint8]
  res512: array[64, uint8]

  ctxS128: Blake2s_128Ctx
  ctxS160: Blake2s_160Ctx
  ctxS224: Blake2s_224Ctx
  ctxS256: Blake2s_256Ctx
  ctxB128: Blake2b_128Ctx
  ctxB160: Blake2b_160Ctx
  ctxB224: Blake2b_224Ctx
  ctxB256: Blake2b_256Ctx
  ctxB384: Blake2b_384Ctx
  ctxB512: Blake2b_512Ctx

benchmark("BLAKE2s-128 Benchmark"):
  for i in 1 .. 1_000_000:
    blake2s_128Init(ctxS128)
    blake2s_128Input(ctxS128, res128)
    res128 = blake2s_128Final(ctxS128)

benchmark("BLAKE2s-160 Benchmark"):
  for i in 1 .. 1_000_000:
    blake2s_160Init(ctxS160)
    blake2s_160Input(ctxS160, res160)
    res160 = blake2s_160Final(ctxS160)

benchmark("BLAKE2s-224 Benchmark"):
  for i in 1 .. 1_000_000:
    blake2s_224Init(ctxS224)
    blake2s_224Input(ctxS224, res224)
    res224 = blake2s_224Final(ctxS224)

benchmark("BLAKE2s-256 Benchmark"):
  for i in 1 .. 1_000_000:
    blake2s_256Init(ctxS256)
    blake2s_256Input(ctxS256, res256)
    res256 = blake2s_256Final(ctxS256)

benchmark("BLAKE2b-128 Benchmark"):
  for i in 1 .. 1_000_000:
    blake2b_128Init(ctxB128)
    blake2b_128Input(ctxB128, res128)
    res128 = blake2b_128Final(ctxB128)

benchmark("BLAKE2b-160 Benchmark"):
  for i in 1 .. 1_000_000:
    blake2b_160Init(ctxB160)
    blake2b_160Input(ctxB160, res160)
    res160 = blake2b_160Final(ctxB160)

benchmark("BLAKE2b-224 Benchmark"):
  for i in 1 .. 1_000_000:
    blake2b_224Init(ctxB224)
    blake2b_224Input(ctxB224, res224)
    res224 = blake2b_224Final(ctxB224)

benchmark("BLAKE2b-256 Benchmark"):
  for i in 1 .. 1_000_000:
    blake2b_256Init(ctxB256)
    blake2b_256Input(ctxB256, res256)
    res256 = blake2b_256Final(ctxB256)

benchmark("BLAKE2b-384 Benchmark"):
  for i in 1 .. 1_000_000:
    blake2b_384Init(ctxB384)
    blake2b_384Input(ctxB384, res384)
    res384 = blake2b_384Final(ctxB384)

benchmark("BLAKE2b-512 Benchmark"):
  for i in 1 .. 1_000_000:
    blake2b_512Init(ctxB512)
    blake2b_512Input(ctxB512, res512)
    res512 = blake2b_512Final(ctxB512)
