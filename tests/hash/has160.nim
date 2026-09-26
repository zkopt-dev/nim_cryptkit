import "../../src/nim_cryptkit/hash/has160"
import "../../src/nim_cryptkit/utils/digits"
import std/[monotimes, times]

var s: seq[uint8] = charToBin("Hello, World!")

var ctx1: HAS160Ctx
has160Init(ctx1)
has160Input(ctx1, s)
let hashResult = binToHex(has160Final(ctx1))
echo "Input : Hello, World!"
echo "HAS-160 Stream : ", hashResult
echo "Standard : 8F6DD8D7C8A04B1CB3831ADC358B1E4AC2ED5984"
doAssert hashResult == "8F6DD8D7C8A04B1CB3831ADC358B1E4AC2ED5984", "HAS-160 Hash Wrong!"

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

var a: array[20, uint8]
var ctx2: HAS160Ctx
benchmark("HAS-160 Benchamark"):
  for i in 1 .. 1_000_000:
    has160Init(ctx2)
    has160Input(ctx2, a)
    a = has160Final(ctx2)
