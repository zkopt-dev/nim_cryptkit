import "../../src/nim_cryptkit/hash/md4"
import "../../src/nim_cryptkit/utils/digits"
import std/[monotimes, times]

var s: seq[uint8] = charToBin("Hello, World!")
var ctx1: MD4Ctx
md4Init(ctx1)
md4Input(ctx1, s)
let hashResult = binToHex(md4Final(ctx1))
echo "MD4 Stream : ", hashResult
echo "MD4 Standard : 94E3CB0FA9AA7A5EE3DB74B79E915989"
echo "Input : Hello, World!"
doAssert hashResult == "94E3CB0FA9AA7A5EE3DB74B79E915989", "MD4 Wrong! got=" & hashResult

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

var a: array[16, uint8]
var ctx2: MD4Ctx

benchmark("MD4 Benchamark"):
  for i in 1 .. 1_000_000:
    md4Init(ctx2)
    md4Input(ctx2, a)
    a = md4Final(ctx2)
