import "../../src/nim_cryptkit/hash/sm3"
import ../../src/nim_cryptkit/utils/digits
import std/[monotimes, times]

var s: seq[uint8] = charToBin("Hello, World!")

# --- Correctness Verification ---
var ctx256: SM3Ctx
sm3Init(ctx256)
sm3Input(ctx256, s)
let hashStream = binToHex(sm3Final(ctx256))

echo "SM3 Stream : ", hashStream
echo "SM3 Standard: 7ED26CBF0BEE4CA7D55C1E64714C4AA7D1F163089EF5CEB603CD102C81FBCBC5"

doAssert hashStream == "7ED26CBF0BEE4CA7D55C1E64714C4AA7D1F163089EF5CEB603CD102C81FBCBC5", "SM3 Stream Wrong! got=" & hashStream

# --- Benchmark ---
template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

var a: array[32, uint8]
var ctxBench: SM3Ctx

benchmark("SM3 Benchmark"):
  for i in 1 .. 1_000_000:
    sm3Init(ctxBench)
    sm3Input(ctxBench, a)
    a = sm3Final(ctxBench)
