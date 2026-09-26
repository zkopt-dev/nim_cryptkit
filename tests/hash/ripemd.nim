import "../../src/nim_cryptkit/hash/ripemd"
import ../../src/nim_cryptkit/utils/digits
import std/[monotimes, times]

var input: seq[uint8] = charToBin("Hello, World!")

# --- RIPEMD-128 ---
var ctx128: RIPEMD128Ctx
echo "Test String : 'Hello, World!'"
ripemd128Init(ctx128)
ripemd128Input(ctx128, input)
let hash128 = binToHex(ripemd128Final(ctx128))
echo "RIPEMD-128 Stream : ", hash128
echo "RIPEMD-128 Standard : 67F9FE75CA2886DC76AD00F7276BDEBA"
doAssert hash128 == "67F9FE75CA2886DC76AD00F7276BDEBA", "RIPEMD-128 Wrong! got=" & hash128

# --- RIPEMD-160 ---
var ctx160: RIPEMD160Ctx
ripemd160Init(ctx160)
ripemd160Input(ctx160, input)
let hash160 = binToHex(ripemd160Final(ctx160))
echo "RIPEMD-160 Stream : ", hash160
echo "RIPEMD-160 Standard : 527A6A4B9A6DA75607546842E0E00105350B1AAF"
doAssert hash160 == "527A6A4B9A6DA75607546842E0E00105350B1AAF", "RIPEMD-160 Wrong! got=" & hash160

# --- RIPEMD-256 ---
var ctx256: RIPEMD256Ctx
ripemd256Init(ctx256)
ripemd256Input(ctx256, input)
let hash256 = binToHex(ripemd256Final(ctx256))
echo "RIPEMD-256 Stream : ", hash256
echo "RIPEMD-256 Standard : 567750C6D34DCBA7AE038A80016F3CA3260EC25BFDB0B68BBB8E730B00B2447D"
doAssert hash256 == "567750C6D34DCBA7AE038A80016F3CA3260EC25BFDB0B68BBB8E730B00B2447D", "RIPEMD-256 Wrong! got=" & hash256

# --- RIPEMD-320 ---
var ctx320: RIPEMD320Ctx
ripemd320Init(ctx320)
ripemd320Input(ctx320, input)
let hash320 = binToHex(ripemd320Final(ctx320))
echo "RIPEMD-320 Stream : ", hash320
echo "RIPEMD-320 Standard : F9832E5BB00576FC56C2221F404EB77ADDEAFE49843C773F0DF3FC5A996D5934F3C96E94AEB80E89"
doAssert hash320 == "F9832E5BB00576FC56C2221F404EB77ADDEAFE49843C773F0DF3FC5A996D5934F3C96E94AEB80E89", "RIPEMD-320 Wrong! got=" & hash320

# --- Benchmark ---
template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

var temp128: array[16, uint8]
var temp160: array[20, uint8]
var temp256: array[32, uint8]
var temp320: array[40, uint8]

benchmark("RIPEMD-128 Benchmark"):
  for i in 1 .. 1_000_000:
    ripemd128Init(ctx128)
    ripemd128Input(ctx128, temp128)
    temp128 = ripemd128Final(ctx128)

benchmark("RIPEMD-160 Benchmark"):
  for i in 1 .. 1_000_000:
    ripemd160Init(ctx160)
    ripemd160Input(ctx160, temp160)
    temp160 = ripemd160Final(ctx160)

benchmark("RIPEMD-256 Benchmark"):
  for i in 1 .. 1_000_000:
    ripemd256Init(ctx256)
    ripemd256Input(ctx256, temp256)
    temp256 = ripemd256Final(ctx256)

benchmark("RIPEMD-320 Benchmark"):
  for i in 1 .. 1_000_000:
    ripemd320Init(ctx320)
    ripemd320Input(ctx320, temp320)
    temp320 = ripemd320Final(ctx320)
