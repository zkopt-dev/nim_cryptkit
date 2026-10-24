import "../../src/nim_cryptkit/hash/keccak"
import "../../src/nim_cryptkit/utils/digits"
import std/[monotimes, times]

var s: seq[uint8] = charToBin("Hello, World!")

# ====================================================================
# SHA3 Tests
# ====================================================================

var sha3_224: SHA3_224Ctx
sha3_224Init(sha3_224)
sha3_224Input(sha3_224, s)
let hashSHA3_224 = binToHex(sha3_224Final(sha3_224))
echo "SHA3-224 Stream : ", hashSHA3_224
echo "SHA3-224 Standard : 853048FB8B11462B6100385633C0CC8DCDC6E2B8E376C28102BC84F2"
doAssert hashSHA3_224 == "853048FB8B11462B6100385633C0CC8DCDC6E2B8E376C28102BC84F2", "SHA3-224 Wrong!"

var sha3_256: SHA3_256Ctx
sha3_256Init(sha3_256)
sha3_256Input(sha3_256, s)
let hashSHA3_256 = binToHex(sha3_256Final(sha3_256))
echo "SHA3-256 Stream : ", hashSHA3_256
echo "SHA3-256 Standard : 1AF17A664E3FA8E419B8BA05C2A173169DF76162A5A286E0C405B460D478F7EF"
doAssert hashSHA3_256 == "1AF17A664E3FA8E419B8BA05C2A173169DF76162A5A286E0C405B460D478F7EF", "SHA3-256 Wrong!"

var sha3_384: SHA3_384Ctx
sha3_384Init(sha3_384)
sha3_384Input(sha3_384, s)
let hashSHA3_384 = binToHex(sha3_384Final(sha3_384))
echo "SHA3-384 Stream : ", hashSHA3_384
echo "SHA3-384 Standard : AA9AD8A49F31D2DDCABBB7010A1566417CFF803FEF50EBA239558826F872E468C5743E7F026B0A8E5B2D7A1CC465CDBE"
doAssert hashSHA3_384 == "AA9AD8A49F31D2DDCABBB7010A1566417CFF803FEF50EBA239558826F872E468C5743E7F026B0A8E5B2D7A1CC465CDBE", "SHA3-384 Wrong!"

var sha3_512: SHA3_512Ctx
sha3_512Init(sha3_512)
sha3_512Input(sha3_512, s)
let hashSHA3_512 = binToHex(sha3_512Final(sha3_512))
echo "SHA3-512 Stream : ", hashSHA3_512
echo "SHA3-512 Standard : 38E05C33D7B067127F217D8C856E554FCFF09C9320B8A5979CE2FF5D95DD27BA35D1FBA50C562DFD1D6CC48BC9C5BAA4390894418CC942D968F97BCB659419ED"
doAssert hashSHA3_512 == "38E05C33D7B067127F217D8C856E554FCFF09C9320B8A5979CE2FF5D95DD27BA35D1FBA50C562DFD1D6CC48BC9C5BAA4390894418CC942D968F97BCB659419ED", "SHA3-512 Wrong!"

# ====================================================================
# Keccak Tests
# ====================================================================

var keccak224: Keccak224Ctx
keccak224Init(keccak224)
keccak224Input(keccak224, s)
let hashKeccak224 = binToHex(keccak224Final(keccak224))
echo "Keccak-224 Stream : ", hashKeccak224
echo "Keccak-224 Standard : 4EAAF0E7A1E400EFBA71130722E1CB4D59B32AFB400E654AFEC4F8CE"
doAssert hashKeccak224 == "4EAAF0E7A1E400EFBA71130722E1CB4D59B32AFB400E654AFEC4F8CE", "Keccak-224 Wrong!"

var keccak256: Keccak256Ctx
keccak256Init(keccak256)
keccak256Input(keccak256, s)
let hashKeccak256 = binToHex(keccak256Final(keccak256))
echo "Keccak-256 Stream : ", hashKeccak256
echo "Keccak-256 Standard : ACAF3289D7B601CBD114FB36C4D29C85BBFD5E133F14CB355C3FD8D99367964F"
doAssert hashKeccak256 == "ACAF3289D7B601CBD114FB36C4D29C85BBFD5E133F14CB355C3FD8D99367964F", "Keccak-256 Wrong!"

var keccak384: Keccak384Ctx
keccak384Init(keccak384)
keccak384Input(keccak384, s)
let hashKeccak384 = binToHex(keccak384Final(keccak384))
echo "Keccak-384 Stream : ", hashKeccak384
echo "Keccak-384 Standard : 4D60892FDE7F967BCABDC47C73122AE6311FA1F9BE90D721DA32030F7467A2E3DB3F9CCB3C746483F9D2B876E39DEF17"
doAssert hashKeccak384 == "4D60892FDE7F967BCABDC47C73122AE6311FA1F9BE90D721DA32030F7467A2E3DB3F9CCB3C746483F9D2B876E39DEF17", "Keccak-384 Wrong!"

var keccak512: Keccak512Ctx
keccak512Init(keccak512)
keccak512Input(keccak512, s)
let hashKeccak512 = binToHex(keccak512Final(keccak512))
echo "Keccak-512 Stream : ", hashKeccak512
echo "Keccak-512 Standard : EDA765576C84C600ED7F5D97510E92703B61F5215DEF2A161037FD9DD1F5B6ED4F86CE46073C0E3F34B52DE0289E9C618798FFF9DD4B1BFE035BDB8645FC6E37"
doAssert hashKeccak512 == "EDA765576C84C600ED7F5D97510E92703B61F5215DEF2A161037FD9DD1F5B6ED4F86CE46073C0E3F34B52DE0289E9C618798FFF9DD4B1BFE035BDB8645FC6E37", "Keccak-512 Wrong!"

# ====================================================================
# Benchmarks
# ====================================================================

var k224: array[28, uint8]
var k256: array[32, uint8]
var k384: array[48, uint8]
var k512: array[64, uint8]
var s224: array[28, uint8]
var s256: array[32, uint8]
var s384: array[48, uint8]
var s512: array[64, uint8]

var ctxK224: Keccak224Ctx
var ctxK256: Keccak256Ctx
var ctxK384: Keccak384Ctx
var ctxK512: Keccak512Ctx
var ctxS224: SHA3_224Ctx
var ctxS256: SHA3_256Ctx
var ctxS384: SHA3_384Ctx
var ctxS512: SHA3_512Ctx

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

# --- Keccak Benchmarks ---

benchmark("Keccak-224 Benchmark"):
  for i in 1 .. 1_000_000:
    keccak224Init(ctxK224)
    keccak224Input(ctxK224, k224)
    k224 = keccak224Final(ctxK224)

benchmark("Keccak-256 Benchmark"):
  for i in 1 .. 1_000_000:
    keccak256Init(ctxK256)
    keccak256Input(ctxK256, k256)
    k256 = keccak256Final(ctxK256)

benchmark("Keccak-384 Benchmark"):
  for i in 1 .. 1_000_000:
    keccak384Init(ctxK384)
    keccak384Input(ctxK384, k384)
    k384 = keccak384Final(ctxK384)

benchmark("Keccak-512 Benchmark"):
  for i in 1 .. 1_000_000:
    keccak512Init(ctxK512)
    keccak512Input(ctxK512, k512)
    k512 = keccak512Final(ctxK512)

# --- SHA3 Benchmarks ---

benchmark("SHA3-224 Benchmark"):
  for i in 1 .. 1_000_000:
    sha3_224Init(ctxS224)
    sha3_224Input(ctxS224, s224)
    s224 = sha3_224Final(ctxS224)

benchmark("SHA3-256 Benchmark"):
  for i in 1 .. 1_000_000:
    sha3_256Init(ctxS256)
    sha3_256Input(ctxS256, s256)
    s256 = sha3_256Final(ctxS256)

benchmark("SHA3-384 Benchmark"):
  for i in 1 .. 1_000_000:
    sha3_384Init(ctxS384)
    sha3_384Input(ctxS384, s384)
    s384 = sha3_384Final(ctxS384)

benchmark("SHA3-512 Benchmark"):
  for i in 1 .. 1_000_000:
    sha3_512Init(ctxS512)
    sha3_512Input(ctxS512, s512)
    s512 = sha3_512Final(ctxS512)
