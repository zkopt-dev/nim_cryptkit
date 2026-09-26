import "../../src/nim_cryptkit/hash/streebog"
import ../../src/nim_cryptkit/utils/digits
import std/[monotimes, times]

var s: seq[uint8] = charToBin("Hello, World!")

# --- Correctness Verification ---
var ctx256: Streebog256Ctx
streebog256Init(ctx256)
streebog256Input(ctx256, s)
let hash256Stream = binToHex(streebog256Final(ctx256))

echo "Streebog-256 Stream : ", hash256Stream
echo "Streebog-256 Standard : EB4672C915B0E4F19CE949B9A8FFF8BA6B36172ED168458D6A75E752E66FAAF3"

doAssert hash256Stream == "EB4672C915B0E4F19CE949B9A8FFF8BA6B36172ED168458D6A75E752E66FAAF3",
  "Streebog-256 Stream Wrong! got=" & hash256Stream

var ctx512: Streebog512Ctx
streebog512Init(ctx512)
streebog512Input(ctx512, s)
let hash512Stream = binToHex(streebog512Final(ctx512))

echo "Streebog-512 Stream : ", hash512Stream
echo "Streebog-512 Standard : 1FD64D8727C5155293239CF53837704E776997B6EC54E923BCF1849A90C0F4C9155254D4A4DBA67A19C380BE3C3C12F9BADD055DD7B7E1F7E6072F83F5BD15F7"

doAssert hash512Stream == "1FD64D8727C5155293239CF53837704E776997B6EC54E923BCF1849A90C0F4C9155254D4A4DBA67A19C380BE3C3C12F9BADD055DD7B7E1F7E6072F83F5BD15F7",
  "Streebog-512 Stream Wrong! got=" & hash512Stream

# --- Benchmark ---
template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

var temp256: array[32, uint8]
var temp512: array[64, uint8]

benchmark("Streebog-256 Benchmark"):
  for i in 1 .. 1_000_000:
    streebog256Init(ctx256)
    streebog256Input(ctx256, temp256)
    temp256 = streebog256Final(ctx256)

benchmark("Streebog-512 Benchmark"):
  for i in 1 .. 1_000_000:
    streebog512Init(ctx512)
    streebog512Input(ctx512, temp512)
    temp512 = streebog512Final(ctx512)
