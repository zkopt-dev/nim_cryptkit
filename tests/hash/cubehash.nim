import "../../src/nim_cryptkit/hash/cubehash"
import ../../src/nim_cryptkit/utils/digits
import std/[monotimes, times]

var sEmpty: seq[uint8] = charToBin("")
var sHello: seq[uint8] = charToBin("Hello")
var sFox: seq[uint8] = charToBin("The quick brown fox jumped over the lazy dog.")
var sFox2: seq[uint8] = charToBin("The quick brown fox jumps over the lazy dog")
var sHex: seq[uint8] = charToBin("78AECC1F4DBF27AC146780EEA8DCC56B")


echo "=== CubeHashHS-512 Test ==="

var hs512Ctx1: CubeHashHS512Ctx
cubeHashHS512Init(hs512Ctx1)
cubeHashHS512Input(hs512Ctx1, sEmpty)
echo "CubeHashHS-512 Stream (Empty)  : ", binToHex(cubeHashHS512Final(hs512Ctx1))
echo "CubeHashHS-512 Standard (Empty): 37045CCA405EE6FBDF815ED8B57C971BB78DAFB58F3EF676C977A716F66DBD8F376FEF59D2E0687CF5608C5DAD53BA42C8456269F3F3BCFB27D9B75CAAA26E11"

var hs512Ctx2: CubeHashHS512Ctx
cubeHashHS512Init(hs512Ctx2)
cubeHashHS512Input(hs512Ctx2, sHello)
echo "CubeHashHS-512 Stream (Hello)  : ", binToHex(cubeHashHS512Final(hs512Ctx2))
echo "CubeHashHS-512 Standard (Hello): A3C2B3D38C940B46B51C286B0159BCEB34FA7AE4D307234F48A2CA4662A21DDC5875FDA2C2A5994BB4D45DBBB3218381174D5DD5F0AAE87DB87D086DFF46E3AE"

var hs512Ctx3: CubeHashHS512Ctx
cubeHashHS512Init(hs512Ctx3)
cubeHashHS512Input(hs512Ctx3, sFox)
echo "CubeHashHS-512 Stream (Fox)    : ", binToHex(cubeHashHS512Final(hs512Ctx3))
echo "CubeHashHS-512 Standard (Fox)  : 8BE880E82D924EAA4C569758429C9EDF93F178B8AD078650C56FA02AFD7D8213FA3B0DA03F75F866C82C24A206EF0709775D1A11813B56075B1AAA29480E1060"


echo "\n=== CubeHashSH-256 Test ==="

var sh256Ctx1: CubeHashSH256Ctx
cubeHashSH256Init(sh256Ctx1)
cubeHashSH256Input(sh256Ctx1, sEmpty)
echo "CubeHashSH-256 Stream (Empty)  : ", binToHex(cubeHashSH256Final(sh256Ctx1))
echo "CubeHashSH-256 Standard (Empty): 44C6DE3AC6C73C391BF0906CB7482600EC06B216C7C54A2A8688A6A42676577D"

var sh256Ctx2: CubeHashSH256Ctx
cubeHashSH256Init(sh256Ctx2)
cubeHashSH256Input(sh256Ctx2, sHello)
echo "CubeHashSH-256 Stream (Hello)  : ", binToHex(cubeHashSH256Final(sh256Ctx2))
echo "CubeHashSH-256 Standard (Hello): E712139E3B892F2F5FE52D0F30D78A0CB16B51B217DA0E4ACB103DD0856F2DB0"

var sh256Ctx3: CubeHashSH256Ctx
cubeHashSH256Init(sh256Ctx3)
cubeHashSH256Input(sh256Ctx3, sFox2)
echo "CubeHashSH-256 Stream (Fox2)   : ", binToHex(cubeHashSH256Final(sh256Ctx3))
echo "CubeHashSH-256 Standard (Fox2) : 5151E251E348CBBFEE46538651C06B138B10EEB71CF6EA6054D7CA5FEC82EB79"

var sh256Ctx4: CubeHashSH256Ctx
cubeHashSH256Init(sh256Ctx4)
cubeHashSH256Input(sh256Ctx4, sHex)
echo "CubeHashSH-256 Stream (Hex)    : ", binToHex(cubeHashSH256Final(sh256Ctx4))
echo "CubeHashSH-256 Standard (Hex)  : DF8C13AD710BA02A0A293B94E144D3B212BBF37CBF51C17E0716F65126A23621"


echo "\n=== CubeHashSH-512 Test ==="

var sh512Ctx1: CubeHashSH512Ctx
cubeHashSH512Init(sh512Ctx1)
cubeHashSH512Input(sh512Ctx1, sEmpty)
echo "CubeHashSH-512 Stream (Empty)  : ", binToHex(cubeHashSH512Final(sh512Ctx1))
echo "CubeHashSH-512 Standard (Empty): 4A1D00BBCFCB5A9562FB981E7F7DB3350FE2658639D948B9D57452C22328BB32F468B072208450BAD5EE178271408BE0B16E5633AC8A1E3CF9864CFBFC8E043A"

var sh512Ctx2: CubeHashSH512Ctx
cubeHashSH512Init(sh512Ctx2)
cubeHashSH512Input(sh512Ctx2, sHello)
echo "CubeHashSH-512 Stream (Hello)  : ", binToHex(cubeHashSH512Final(sh512Ctx2))
echo "CubeHashSH-512 Standard (Hello): DCC0503AAE279A3C8C95FA1181D37C418783204E2E3048A081392FD61BACE883A1F7C4C96B16B4060C42104F1CE45A622F1A9ABAEB994BEB107FED53A78F588C"

var sh512Ctx3: CubeHashSH512Ctx
cubeHashSH512Init(sh512Ctx3)
cubeHashSH512Input(sh512Ctx3, sFox2)
echo "CubeHashSH-512 Stream (Fox2)   : ", binToHex(cubeHashSH512Final(sh512Ctx3))
echo "CubeHashSH-512 Standard (Fox2) : BDBA44A28CD16B774BDF3C9511DEF1A2BAF39D4EF98B92C27CF5E37BEB8990B7CDB6575DAE1A548330780810618B8A5C351C1368904DB7EBDF8857D596083A86"


template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

var
  res128: array[16, uint8]
  res160: array[20, uint8]
  res192: array[24, uint8]
  res224: array[28, uint8]
  res256: array[32, uint8]
  res384: array[48, uint8]
  res512: array[64, uint8]

  ctxHS128: CubeHashHS128Ctx
  ctxHS160: CubeHashHS160Ctx
  ctxHS192: CubeHashHS192Ctx
  ctxHS224: CubeHashHS224Ctx
  ctxHS256: CubeHashHS256Ctx
  ctxHS384: CubeHashHS384Ctx
  ctxHS512: CubeHashHS512Ctx

  ctxSH128: CubeHashSH128Ctx
  ctxSH160: CubeHashSH160Ctx
  ctxSH192: CubeHashSH192Ctx
  ctxSH224: CubeHashSH224Ctx
  ctxSH256: CubeHashSH256Ctx
  ctxSH384: CubeHashSH384Ctx
  ctxSH512: CubeHashSH512Ctx

benchmark("CubeHashHS-128 Benchmark"):
  for i in 1 .. 1_000_000:
    cubeHashHS128Init(ctxHS128)
    cubeHashHS128Input(ctxHS128, res128)
    res128 = cubeHashHS128Final(ctxHS128)

benchmark("CubeHashHS-160 Benchmark"):
  for i in 1 .. 1_000_000:
    cubeHashHS160Init(ctxHS160)
    cubeHashHS160Input(ctxHS160, res160)
    res160 = cubeHashHS160Final(ctxHS160)

benchmark("CubeHashHS-192 Benchmark"):
  for i in 1 .. 1_000_000:
    cubeHashHS192Init(ctxHS192)
    cubeHashHS192Input(ctxHS192, res192)
    res192 = cubeHashHS192Final(ctxHS192)

benchmark("CubeHashHS-224 Benchmark"):
  for i in 1 .. 1_000_000:
    cubeHashHS224Init(ctxHS224)
    cubeHashHS224Input(ctxHS224, res224)
    res224 = cubeHashHS224Final(ctxHS224)

benchmark("CubeHashHS-256 Benchmark"):
  for i in 1 .. 1_000_000:
    cubeHashHS256Init(ctxHS256)
    cubeHashHS256Input(ctxHS256, res256)
    res256 = cubeHashHS256Final(ctxHS256)

benchmark("CubeHashHS-384 Benchmark"):
  for i in 1 .. 1_000_000:
    cubeHashHS384Init(ctxHS384)
    cubeHashHS384Input(ctxHS384, res384)
    res384 = cubeHashHS384Final(ctxHS384)

benchmark("CubeHashHS-512 Benchmark"):
  for i in 1 .. 1_000_000:
    cubeHashHS512Init(ctxHS512)
    cubeHashHS512Input(ctxHS512, res512)
    res512 = cubeHashHS512Final(ctxHS512)

benchmark("CubeHashSH-128 Benchmark"):
  for i in 1 .. 1_000_000:
    cubeHashSH128Init(ctxSH128)
    cubeHashSH128Input(ctxSH128, res128)
    res128 = cubeHashSH128Final(ctxSH128)

benchmark("CubeHashSH-160 Benchmark"):
  for i in 1 .. 1_000_000:
    cubeHashSH160Init(ctxSH160)
    cubeHashSH160Input(ctxSH160, res160)
    res160 = cubeHashSH160Final(ctxSH160)

benchmark("CubeHashSH-192 Benchmark"):
  for i in 1 .. 1_000_000:
    cubeHashSH192Init(ctxSH192)
    cubeHashSH192Input(ctxSH192, res192)
    res192 = cubeHashSH192Final(ctxSH192)

benchmark("CubeHashSH-224 Benchmark"):
  for i in 1 .. 1_000_000:
    cubeHashSH224Init(ctxSH224)
    cubeHashSH224Input(ctxSH224, res224)
    res224 = cubeHashSH224Final(ctxSH224)

benchmark("CubeHashSH-256 Benchmark"):
  for i in 1 .. 1_000_000:
    cubeHashSH256Init(ctxSH256)
    cubeHashSH256Input(ctxSH256, res256)
    res256 = cubeHashSH256Final(ctxSH256)

benchmark("CubeHashSH-384 Benchmark"):
  for i in 1 .. 1_000_000:
    cubeHashSH384Init(ctxSH384)
    cubeHashSH384Input(ctxSH384, res384)
    res384 = cubeHashSH384Final(ctxSH384)

benchmark("CubeHashSH-512 Benchmark"):
  for i in 1 .. 1_000_000:
    cubeHashSH512Init(ctxSH512)
    cubeHashSH512Input(ctxSH512, res512)
    res512 = cubeHashSH512Final(ctxSH512)
