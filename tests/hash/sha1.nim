import "../../src/nim_cryptkit/hash/sha1"
import ../../src/nim_cryptkit/utils/digits
import std/[monotimes, times]

var s: seq[uint8] = charToBin("Hello, World!")

# --- Correctness Verification ---
var ctx: SHA1Ctx
sha1Init(ctx)
sha1Input(ctx, s)
let hashStream = binToHex(sha1Final(ctx))
let hashOne = binToHex(sha1One(s))

echo "SHA1 Stream : ", hashStream
echo "SHA1 One    : ", hashOne
echo "SHA1 Standard: 0A0A9F2A6772942557AB5355D76AF442F8F65E01"
echo "Input : Hello, World!"

doAssert hashStream == "0A0A9F2A6772942557AB5355D76AF442F8F65E01", "SHA-1 Stream Wrong! got=" & hashStream
doAssert hashOne == "0A0A9F2A6772942557AB5355D76AF442F8F65E01", "SHA-1 One Wrong! got=" & hashOne

# --- Benchmark ---
template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

var a: array[20, uint8]
var ctx2: SHA1Ctx

benchmark("SHA-1 Benchmark"):
  for i in 1 .. 1_000_000:
    sha1Init(ctx2)
    sha1Input(ctx2, a)
    a = sha1Final(ctx2)
