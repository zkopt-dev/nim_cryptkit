import "../../src/nim_cryptkit/hash/whirlpool"
import ../../src/nim_cryptkit/utils/digits
import std/[monotimes, times]

var s: seq[uint8] = charToBin("Hello, World!")

# --- Correctness Verification ---
var ctx: WhirlpoolCtx
whirlpoolInit(ctx)
whirlpoolInput(ctx, s)
let hashStream = binToHex(whirlpoolFinal(ctx))

echo "Input Standard : ", binToHex(s)
echo "Whirlpool Stream : ", hashStream
echo "Whirlpool Standard : 3D837C9EF7BB291BD1DCFC05D3004AF2EEB8C631DD6A6C4BA35159B8889DE4B1EC44076CE7A8F7BFA497E4D9DCB7C29337173F78D06791F3C3D9E00CC6017F0B"

doAssert hashStream == "3D837C9EF7BB291BD1DCFC05D3004AF2EEB8C631DD6A6C4BA35159B8889DE4B1EC44076CE7A8F7BFA497E4D9DCB7C29337173F78D06791F3C3D9E00CC6017F0B",
  "Whirlpool Stream Wrong! got=" & hashStream

# --- Benchmark ---
template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

var a: array[64, uint8]

benchmark("Whirlpool"):
  for i in 1 .. 1_000_000:
    whirlpoolInit(ctx)
    whirlpoolInput(ctx, a)
    a = whirlpoolFinal(ctx)
