import "../../src/nim_cryptkit/hash/gosthash"
import "../../src/nim_cryptkit/utils/digits"
import std/[monotimes, times]

var s: seq[uint8] = charToBin("Hello, World!")

var ctx: GOSTHashCtx
gostHashInit(ctx)
gostHashInput(ctx, s)
let hashResult = binToHex(gostHashFinal(ctx))
echo "GOST Hash Stream : ", hashResult
echo "GOST Hash Standard : 9251C7D7AD6BBF5A14A67002BF8261E8AD742FEAF3DD4F8C95B8964B4203DA80"
echo "Input : Hello, World!"
echo "S-Box : D-TEST"
doAssert hashResult == "9251C7D7AD6BBF5A14A67002BF8261E8AD742FEAF3DD4F8C95B8964B4203DA80", "GOST Hash Wrong!"

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

var a: array[32, uint8]
var ctx2: GOSTHashCtx
benchmark("GOST Hash Benchamark"):
  for i in 1 .. 1_000_000:
    gostHashInit(ctx2)
    gostHashInput(ctx2, a)
    a = gostHashFinal(ctx2)
