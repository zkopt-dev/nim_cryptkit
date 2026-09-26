import "../../src/nim_cryptkit/hash/groestl"
import "../../src/nim_cryptkit/utils/digits"
import std/[monotimes, times]

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

# ====================================================================
# Groestl-224 Test
# ====================================================================
var ctx224: Groestl224Ctx

var input224_1: seq[uint8] = hexToBin("CC").value
echo "Groestl-224 Input 1 : ", binToHex(input224_1)
groestl224Init(ctx224)
groestl224Input(ctx224, input224_1)
var output224_1: array[28, uint8] = groestl224Final(ctx224)
let hash224_1 = binToHex(output224_1)
echo "Groestl-224 Stream 1 : ", hash224_1
echo "Groestl-224 Standard 1: 62E367662ADF9317154F877FD740C23FC2356080B477DAC847BE2EB2"
doAssert hash224_1 == "62E367662ADF9317154F877FD740C23FC2356080B477DAC847BE2EB2", "Groestl-224 Test 1 Wrong!"

var input224_2: seq[uint8] = hexToBin("1F877C").value
echo "Groestl-224 Input 2 : ", binToHex(input224_2)
groestl224Init(ctx224)
groestl224Input(ctx224, input224_2)
var output224_2: array[28, uint8] = groestl224Final(ctx224)
let hash224_2 = binToHex(output224_2)
echo "Groestl-224 Stream 2 : ", hash224_2
echo "Groestl-224 Standard 2: 1DC3EF787D0D92A2E7B66E28A5BBC14A0F533E3946F3EEECEDC001F9"
doAssert hash224_2 == "1DC3EF787D0D92A2E7B66E28A5BBC14A0F533E3946F3EEECEDC001F9", "Groestl-224 Test 2 Wrong!"
echo ""

# ====================================================================
# Groestl-256 Test
# ====================================================================
var ctx256: Groestl256Ctx

var input256_1: seq[uint8] = hexToBin("1F877C").value
echo "Groestl-256 Input 1 : ", binToHex(input256_1)
groestl256Init(ctx256)
groestl256Input(ctx256, input256_1)
var output256_1: array[32, uint8] = groestl256Final(ctx256)
let hash256_1 = binToHex(output256_1)
echo "Groestl-256 Stream 1 : ", hash256_1
echo "Groestl-256 Standard 1: 05FE7DE2D8CE1770DF766739F788037D0CF2CA7C2B7620835CC34F45B3FCF919"
doAssert hash256_1 == "05FE7DE2D8CE1770DF766739F788037D0CF2CA7C2B7620835CC34F45B3FCF919", "Groestl-256 Test 1 Wrong!"

var input256_2: seq[uint8] = hexToBin("C71BD7941F41DF044A2927A8FF55B4B467C33D089F0988AA253D294ADDBDB32530C0D4208B10D9959823F0C0F0734684006DF79F7099870F6BF53211A88D").value
echo "Groestl-256 Input 2 : ", binToHex(input256_2)
groestl256Init(ctx256)
groestl256Input(ctx256, input256_2)
var output256_2: array[32, uint8] = groestl256Final(ctx256)
let hash256_2 = binToHex(output256_2)
echo "Groestl-256 Stream 2 : ", hash256_2
echo "Groestl-256 Standard 2: 74621CA404EE51690DC5AB30CCB6219FB458BF35F534068AAC14C357C49A3CD7"
doAssert hash256_2 == "74621CA404EE51690DC5AB30CCB6219FB458BF35F534068AAC14C357C49A3CD7", "Groestl-256 Test 2 Wrong!"
echo ""

# ====================================================================
# Groestl-384 Test
# ====================================================================
var ctx384: Groestl384Ctx

var input384_1: seq[uint8] = hexToBin("C6F50BB74E29").value
echo "Groestl-384 Input 1 : ", binToHex(input384_1)
groestl384Init(ctx384)
groestl384Input(ctx384, input384_1)
var output384_1: array[48, uint8] = groestl384Final(ctx384)
let hash384_1 = binToHex(output384_1)
echo "Groestl-384 Stream 1 : ", hash384_1
echo "Groestl-384 Standard 1: 3E3197BA9ECA972F90EA2C04FF35B8410D96A949EBE4847FFF070497A20281B4AAB2BBE23DF5381CB1BBA90BD67C627C"
doAssert hash384_1 == "3E3197BA9ECA972F90EA2C04FF35B8410D96A949EBE4847FFF070497A20281B4AAB2BBE23DF5381CB1BBA90BD67C627C", "Groestl-384 Test 1 Wrong!"

var input384_2: seq[uint8] = hexToBin("4B127FDE5DE733A1680C2790363627E63AC8A3F1B4707D982CAEA258655D9BF18F89AFE54127482BA01E08845594B671306A025C9A5C5B6F93B0A39522DC877437BE5C2436CBF300CE7AB6747934FCFC30AEAAF6").value
echo "Groestl-384 Input 2 : ", binToHex(input384_2)
groestl384Init(ctx384)
groestl384Input(ctx384, input384_2)
var output384_2: array[48, uint8] = groestl384Final(ctx384)
let hash384_2 = binToHex(output384_2)
echo "Groestl-384 Stream 2 : ", hash384_2
echo "Groestl-384 Standard 2: 51FB0A99436C992827E75AA741C03703D568FC6D6BE7C6DAA28E9CB60D76F871B6DE47361AB778419D8ABA7EF18126CF"
doAssert hash384_2 == "51FB0A99436C992827E75AA741C03703D568FC6D6BE7C6DAA28E9CB60D76F871B6DE47361AB778419D8ABA7EF18126CF", "Groestl-384 Test 2 Wrong!"
echo ""

# ====================================================================
# Groestl-512 Test
# ====================================================================
var ctx512: Groestl512Ctx

var input512_1: seq[uint8] = hexToBin("C1ECFDFC").value
echo "Groestl-512 Input 1 : ", binToHex(input512_1)
groestl512Init(ctx512)
groestl512Input(ctx512, input512_1)
var output512_1: array[64, uint8] = groestl512Final(ctx512)
let hash512_1 = binToHex(output512_1)
echo "Groestl-512 Stream 1 : ", hash512_1
echo "Groestl-512 Standard 1: 4726D760203C1EAF847F6837C74C16ADCEF5B55EAD5768A7C13E21A33D0D7B740F52DE8C81356DA63DABA791DA6680AF015DEB81246550201F232822BB087CE5"
doAssert hash512_1 == "4726D760203C1EAF847F6837C74C16ADCEF5B55EAD5768A7C13E21A33D0D7B740F52DE8C81356DA63DABA791DA6680AF015DEB81246550201F232822BB087CE5", "Groestl-512 Test 1 Wrong!"

var input512_2: seq[uint8] = hexToBin("F690A132AB46B28EDFA6479283D6444E371C6459108AFD9C35DBD235E0B6B6FF4C4EA58E7554BD002460433B2164CA51E868F7947D7D7A0D792E4ABF0BE5F450853CC40D85485B2B8857EA31B5EA6E4CCFA2F3A7EF3380066D7D8979FDAC618AAD3D7E886DEA4F005AE4AD05E5065F").value
echo "Groestl-512 Input 2 : ", binToHex(input512_2)
groestl512Init(ctx512)
groestl512Input(ctx512, input512_2)
var output512_2: array[64, uint8] = groestl512Final(ctx512)
let hash512_2 = binToHex(output512_2)
echo "Groestl-512 Stream 2 : ", hash512_2
echo "Groestl-512 Standard 2: 814A596249AC113CF394A5E348DF55293BCE8401BF9F0EC34114BB55EA1A047283AF655D45AC45717C60F66398A36CD1F7F354AE6FD327D6F50F1C978C704433"
doAssert hash512_2 == "814A596249AC113CF394A5E348DF55293BCE8401BF9F0EC34114BB55EA1A047283AF655D45AC45717C60F66398A36CD1F7F354AE6FD327D6F50F1C978C704433", "Groestl-512 Test 2 Wrong!"
echo ""

# ====================================================================
# 1,000,000 Chaining Benchmarks
# ====================================================================
var res224: array[28, uint8]
var res256: array[32, uint8]
var res384: array[48, uint8]
var res512: array[64, uint8]

benchmark("Groestl-224"):
  for i in 1 .. 1_000_000:
    groestl224Init(ctx224)
    groestl224Input(ctx224, res224)
    res224 = groestl224Final(ctx224)

benchmark("Groestl-256"):
  for i in 1 .. 1_000_000:
    groestl256Init(ctx256)
    groestl256Input(ctx256, res256)
    res256 = groestl256Final(ctx256)

benchmark("Groestl-384"):
  for i in 1 .. 1_000_000:
    groestl384Init(ctx384)
    groestl384Input(ctx384, res384)
    res384 = groestl384Final(ctx384)

benchmark("Groestl-512"):
  for i in 1 .. 1_000_000:
    groestl512Init(ctx512)
    groestl512Input(ctx512, res512)
    res512 = groestl512Final(ctx512)
