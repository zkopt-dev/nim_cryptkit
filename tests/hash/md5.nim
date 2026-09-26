import "../../src/nim_cryptkit/hash/md5"
import "../../src/nim_cryptkit/utils/digits"
import std/[monotimes, times]

var s: seq[uint8] = charToBin("Hello, World!")
var ctx: MD5Ctx
md5Init(ctx)
md5Input(ctx, s)
let hashResult = binToHex(md5Final(ctx))
echo "MD5Stream : ", hashResult
echo "MD5One : ", binToHex(md5One(s))
echo "MD5 Standard : 65A8E27D8879283831B664BD8B7F0AD4"
echo "Input : Hello, World!"
doAssert hashResult == "65A8E27D8879283831B664BD8B7F0AD4", "MD5 Wrong! got=" & hashResult

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

var a: array[16, uint8]
var ctx2: MD5Ctx

benchmark("MD5 Benchamark"):
  for i in 1 .. 1_000_000:
    md5Init(ctx2)
    md5Input(ctx2, a)
    a = md5Final(ctx2)
