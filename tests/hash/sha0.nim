import "../../src/nim_cryptkit/hash/sha0"
import ../../src/nim_cryptkit/utils/digits
import std/[monotimes, times]

var s: seq[uint8] = charToBin("Hello, World!")

# --- Correctness Verification ---
var ctx: SHA0Ctx
sha0Init(ctx)
sha0Input(ctx, s)
let hashStream = binToHex(sha0Final(ctx))
let hashOne = binToHex(sha0One(s))

echo "SHA0 Stream : ", hashStream
echo "SHA0 One    : ", hashOne
echo "SHA0 Standard: 5A5588F0407C6AE9A988758E76965F841B299229"
echo "Input : Hello, World!"

doAssert hashStream == "5A5588F0407C6AE9A988758E76965F841B299229", "SHA-0 Stream Wrong! got=" & hashStream
doAssert hashOne == "5A5588F0407C6AE9A988758E76965F841B299229", "SHA-0 One Wrong! got=" & hashOne

# --- Benchmark ---
template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

var a: array[20, uint8]
var ctx2: SHA0Ctx

benchmark("SHA-0 Benchmark"):
  for i in 1 .. 1_000_000:
    sha0Init(ctx2)
    sha0Input(ctx2, a)
    a = sha0Final(ctx2)
