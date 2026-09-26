import "../../src/nim_cryptkit/hash/md2"
import "../../src/nim_cryptkit/utils/digits"
import std/[monotimes, times]

var s: seq[uint8] = charToBin("Hello, World!")
var ctx1: MD2Ctx
md2Init(ctx1)
md2Input(ctx1, s)
let hashResult = binToHex(md2Final(ctx1))
echo "MD2 Stream : ", hashResult
echo "MD2 Standard : 1C8F1E6A94AAA7145210BF90BB52871A"
echo "Input : Hello, World!"
doAssert hashResult == "1C8F1E6A94AAA7145210BF90BB52871A", "MD2 Wrong! got=" & hashResult

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

var a: array[16, uint8]
var ctx2: MD2Ctx

benchmark("MD2 Benchamark"):
  for i in 1 .. 1_000_000:
    md2Init(ctx2)
    md2Input(ctx2, a)
    a = md2Final(ctx2)
