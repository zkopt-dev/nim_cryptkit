import "../../src/nim_cryptkit/hash/kupyna"
import "../../src/nim_cryptkit/utils/digits"
import std/[monotimes, times]

# test code
var s: seq[uint8] = charToBin("012345678901234567890123456789012345678901234567890123456789012")
echo "Input Message : 012345678901234567890123456789012345678901234567890123456789012"

var ctx256: Kupyna256Ctx
kupyna256Init(ctx256)
kupyna256Input(ctx256, s)
let hash256 = binToHex(kupyna256Final(ctx256))
echo "Kupyna-256 Stream : ", hash256
echo "Kupyna-256 Standard : 5458DA58F28E137100D564C6EA201356AE31C25F001E07E5C13090EDD353A18F"
doAssert hash256 == "5458DA58F28E137100D564C6EA201356AE31C25F001E07E5C13090EDD353A18F", "Kupyna-256 Wrong!"

var ctx384: Kupyna384Ctx
kupyna384Init(ctx384)
kupyna384Input(ctx384, s)
let hash384 = binToHex(kupyna384Final(ctx384))
echo "Kupyna-384 Stream : ", hash384
echo "Kupyna-384 Standard : 3A7CEBFF36805EBA4468CFE8CB33C68FC57B61EF61D8AC65629EB3291D62BC7EFB98AA422B2A2AA9D8FB236634D49AA9"
doAssert hash384 == "3A7CEBFF36805EBA4468CFE8CB33C68FC57B61EF61D8AC65629EB3291D62BC7EFB98AA422B2A2AA9D8FB236634D49AA9", "Kupyna-384 Wrong!"

var ctx512: Kupyna512Ctx
kupyna512Init(ctx512)
kupyna512Input(ctx512, s)
let hash512 = binToHex(kupyna512Final(ctx512))
echo "Kupyna-512 Stream : ", hash512
echo "Kupyna-512 Standard : 9DC29544CD5F184CF5CFE0CCC9AB895C3A7CEBFF36805EBA4468CFE8CB33C68FC57B61EF61D8AC65629EB3291D62BC7EFB98AA422B2A2AA9D8FB236634D49AA9"
doAssert hash512 == "9DC29544CD5F184CF5CFE0CCC9AB895C3A7CEBFF36805EBA4468CFE8CB33C68FC57B61EF61D8AC65629EB3291D62BC7EFB98AA422B2A2AA9D8FB236634D49AA9", "Kupyna-512 Wrong!"

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

var temp256: array[32, uint8]
var temp384: array[48, uint8]
var temp512: array[64, uint8]

benchmark("Kupyna-256 Benchmark"):
  for i in 1 .. 1_000_000:
    kupyna256Init(ctx256)
    kupyna256Input(ctx256, temp256)
    temp256 = kupyna256Final(ctx256)

benchmark("Kupyna-384 Benchmark"):
  for i in 1 .. 1_000_000:
    kupyna384Init(ctx384)
    kupyna384Input(ctx384, temp384)
    temp384 = kupyna384Final(ctx384)

benchmark("Kupyna-512 Benchmark"):
  for i in 1 .. 1_000_000:
    kupyna512Init(ctx512)
    kupyna512Input(ctx512, temp512)
    temp512 = kupyna512Final(ctx512)
