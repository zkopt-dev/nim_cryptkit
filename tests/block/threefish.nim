import "../../src/nim_cryptkit/block/threefish"
import "../../src/nim_cryptkit/utils/digits"
import std/[monotimes, times]

echo "Threefish Series Test & Benchmark"

# ============================================================
# Threefish-256 Test
# ============================================================

var ctx256: Threefish256Ctx

var key256: array[32, uint8] = [
  0x10'u8, 0x11'u8, 0x12'u8, 0x13'u8, 0x14'u8, 0x15'u8, 0x16'u8, 0x17'u8,
  0x18'u8, 0x19'u8, 0x1A'u8, 0x1B'u8, 0x1C'u8, 0x1D'u8, 0x1E'u8, 0x1F'u8,
  0x20'u8, 0x21'u8, 0x22'u8, 0x23'u8, 0x24'u8, 0x25'u8, 0x26'u8, 0x27'u8,
  0x28'u8, 0x29'u8, 0x2A'u8, 0x2B'u8, 0x2C'u8, 0x2D'u8, 0x2E'u8, 0x2F'u8
]

var tweak256: array[2, uint64] = [
  0x0706050403020100'u64,
  0x0F0E0D0C0B0A0908'u64
]

var text256: array[32, uint8] = [
  0xFF'u8, 0xFE'u8, 0xFD'u8, 0xFC'u8, 0xFB'u8, 0xFA'u8, 0xF9'u8, 0xF8'u8,
  0xF7'u8, 0xF6'u8, 0xF5'u8, 0xF4'u8, 0xF3'u8, 0xF2'u8, 0xF1'u8, 0xF0'u8,
  0xEF'u8, 0xEE'u8, 0xED'u8, 0xEC'u8, 0xEB'u8, 0xEA'u8, 0xE9'u8, 0xE8'u8,
  0xE7'u8, 0xE6'u8, 0xE5'u8, 0xE4'u8, 0xE3'u8, 0xE2'u8, 0xE1'u8, 0xE0'u8
]

var encrypt256: array[32, uint8]
var decrypt256: array[32, uint8]

let pt256 = binToHex(text256)
threefish256Init(ctx256, key256, tweak256)
echo "---"
echo "Threefish-256 Test"
echo "TF-256 Key Standard        : ", binToHex(key256)
echo "TF-256 Plain Text Standard : ", pt256
threefish256Encrypt(ctx256, text256, encrypt256)
echo "TF-256 Cipher Text Standard: E0D091FF0EEA8FDFC98192E62ED80AD59D865D08588DF476657056B5955E97DF"
let ct256 = binToHex(encrypt256)
echo "TF-256 Cipher Text State   : ", ct256
doAssert ct256 == "E0D091FF0EEA8FDFC98192E62ED80AD59D865D08588DF476657056B5955E97DF",
    "Threefish-256 Encrypt Wrong!"
threefish256Decrypt(ctx256, encrypt256, decrypt256)
echo "TF-256 Plain Text State    : ", binToHex(decrypt256)
doAssert binToHex(decrypt256) == pt256, "Threefish-256 Decrypt Wrong!"


# ============================================================
# Threefish-512 Test
# ============================================================

var ctx512: Threefish512Ctx

var key512: array[64, uint8] = [
  0x10'u8, 0x11'u8, 0x12'u8, 0x13'u8, 0x14'u8, 0x15'u8, 0x16'u8, 0x17'u8,
  0x18'u8, 0x19'u8, 0x1A'u8, 0x1B'u8, 0x1C'u8, 0x1D'u8, 0x1E'u8, 0x1F'u8,
  0x20'u8, 0x21'u8, 0x22'u8, 0x23'u8, 0x24'u8, 0x25'u8, 0x26'u8, 0x27'u8,
  0x28'u8, 0x29'u8, 0x2A'u8, 0x2B'u8, 0x2C'u8, 0x2D'u8, 0x2E'u8, 0x2F'u8,
  0x30'u8, 0x31'u8, 0x32'u8, 0x33'u8, 0x34'u8, 0x35'u8, 0x36'u8, 0x37'u8,
  0x38'u8, 0x39'u8, 0x3A'u8, 0x3B'u8, 0x3C'u8, 0x3D'u8, 0x3E'u8, 0x3F'u8,
  0x40'u8, 0x41'u8, 0x42'u8, 0x43'u8, 0x44'u8, 0x45'u8, 0x46'u8, 0x47'u8,
  0x48'u8, 0x49'u8, 0x4A'u8, 0x4B'u8, 0x4C'u8, 0x4D'u8, 0x4E'u8, 0x4F'u8
]

var tweak512: array[2, uint64] = [
  0x0706050403020100'u64,
  0x0F0E0D0C0B0A0908'u64
]

var text512: array[64, uint8] = [
  0xFF'u8, 0xFE'u8, 0xFD'u8, 0xFC'u8, 0xFB'u8, 0xFA'u8, 0xF9'u8, 0xF8'u8,
  0xF7'u8, 0xF6'u8, 0xF5'u8, 0xF4'u8, 0xF3'u8, 0xF2'u8, 0xF1'u8, 0xF0'u8,
  0xEF'u8, 0xEE'u8, 0xED'u8, 0xEC'u8, 0xEB'u8, 0xEA'u8, 0xE9'u8, 0xE8'u8,
  0xE7'u8, 0xE6'u8, 0xE5'u8, 0xE4'u8, 0xE3'u8, 0xE2'u8, 0xE1'u8, 0xE0'u8,
  0xDF'u8, 0xDE'u8, 0xDD'u8, 0xDC'u8, 0xDB'u8, 0xDA'u8, 0xD9'u8, 0xD8'u8,
  0xD7'u8, 0xD6'u8, 0xD5'u8, 0xD4'u8, 0xD3'u8, 0xD2'u8, 0xD1'u8, 0xD0'u8,
  0xCF'u8, 0xCE'u8, 0xCD'u8, 0xCC'u8, 0xCB'u8, 0xCA'u8, 0xC9'u8, 0xC8'u8,
  0xC7'u8, 0xC6'u8, 0xC5'u8, 0xC4'u8, 0xC3'u8, 0xC2'u8, 0xC1'u8, 0xC0'u8
]

var encrypt512: array[64, uint8]
var decrypt512: array[64, uint8]

let pt512 = binToHex(text512)
threefish512Init(ctx512, key512, tweak512)
echo "---"
echo "Threefish-512 Test"
echo "TF-512 Key Standard        : ", binToHex(key512)
echo "TF-512 Plain Text Standard : ", pt512
threefish512Encrypt(ctx512, text512, encrypt512)
echo "TF-512 Cipher Text Standard: E304439626D45A2CB401CAD8D636249A6338330EB06D45DD8B36B90E97254779272A0A8D99463504784420EA18C9A725AF11DFFEA10162348927673D5C1CAF3D"
let ct512 = binToHex(encrypt512)
echo "TF-512 Cipher Text State   : ", ct512
doAssert ct512 == "E304439626D45A2CB401CAD8D636249A6338330EB06D45DD8B36B90E97254779272A0A8D99463504784420EA18C9A725AF11DFFEA10162348927673D5C1CAF3D",
    "Threefish-512 Encrypt Wrong!"
threefish512Decrypt(ctx512, encrypt512, decrypt512)
echo "TF-512 Plain Text State    : ", binToHex(decrypt512)
doAssert binToHex(decrypt512) == pt512, "Threefish-512 Decrypt Wrong!"


# ============================================================
# Threefish-1024 Test (Zero Vector)
# ============================================================

var ctx1024: Threefish1024Ctx

var key1024: array[128, uint8]
var tweak1024: array[2, uint64] = [0'u64, 0'u64]
var text1024: array[128, uint8]

zeroMem(addr key1024[0], 128)
zeroMem(addr text1024[0], 128)

var encrypt1024: array[128, uint8]
var decrypt1024: array[128, uint8]

let pt1024 = binToHex(text1024)

threefish1024Init(ctx1024, key1024, tweak1024)
echo "---"
echo "Threefish-1024 Test (Zero Vector)"
echo "TF-1024 Key Standard        : ", binToHex(key1024)
echo "TF-1024 Plain Text Standard : ", pt1024
threefish1024Encrypt(ctx1024, text1024, encrypt1024)
echo "TF-1024 Cipher Text Standard: F05C3D0A3D05B304F785DDC7D1E036015C8AA76E2F217B06C6E1544C0BC1A90DF0ACCB9473C24E0FD54FEA68057F43329CB454761D6DF5CF7B2E9B3614FBD5A20B2E4760B40603540D82EABC5482C171C832AFBE68406BC39500367A592943FA9A5B4A43286CA3C4CF46104B443143D560A4B230488311DF4FEEF7E1DFE8391E"
let ct1024 = binToHex(encrypt1024)
echo "TF-1024 Cipher Text State   : ", ct1024
doAssert ct1024 == "F05C3D0A3D05B304F785DDC7D1E036015C8AA76E2F217B06C6E1544C0BC1A90DF0ACCB9473C24E0FD54FEA68057F43329CB454761D6DF5CF7B2E9B3614FBD5A20B2E4760B40603540D82EABC5482C171C832AFBE68406BC39500367A592943FA9A5B4A43286CA3C4CF46104B443143D560A4B230488311DF4FEEF7E1DFE8391E",
    "Threefish-1024 Encrypt Wrong!"
threefish1024Decrypt(ctx1024, encrypt1024, decrypt1024)
echo "TF-1024 Plain Text State    : ", binToHex(decrypt1024)
doAssert binToHex(decrypt1024) == pt1024, "Threefish-1024 Decrypt Wrong!"
echo "---"


# ============================================================
# Benchmark
# ============================================================

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

# Threefish-256 Benchmarks
benchmark("Threefish-256 Init"):
  for i in 1 .. 1_000_000:
    threefish256Init(ctx256, key256, tweak256)

benchmark("Threefish-256 Encrypt"):
  for i in 1 .. 1_000_000:
    threefish256Encrypt(ctx256, text256, text256)

benchmark("Threefish-256 Decrypt"):
  for i in 1 .. 1_000_000:
    threefish256Decrypt(ctx256, text256, text256)

# Threefish-512 Benchmarks
benchmark("Threefish-512 Init"):
  for i in 1 .. 1_000_000:
    threefish512Init(ctx512, key512, tweak512)

benchmark("Threefish-512 Encrypt"):
  for i in 1 .. 1_000_000:
    threefish512Encrypt(ctx512, text512, text512)

benchmark("Threefish-512 Decrypt"):
  for i in 1 .. 1_000_000:
    threefish512Decrypt(ctx512, text512, text512)

# Threefish-1024 Benchmarks
benchmark("Threefish-1024 Init"):
  for i in 1 .. 1_000_000:
    threefish1024Init(ctx1024, key1024, tweak1024)

benchmark("Threefish-1024 Encrypt"):
  for i in 1 .. 1_000_000:
    threefish1024Encrypt(ctx1024, text1024, text1024)

benchmark("Threefish-1024 Decrypt"):
  for i in 1 .. 1_000_000:
    threefish1024Decrypt(ctx1024, text1024, text1024)
