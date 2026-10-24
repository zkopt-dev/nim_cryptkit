import "../../src/nim_cryptkit/hash/echo"
import "../../src/nim_cryptkit/utils/digits"
import std/[monotimes, times]

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

var ctx224: ECHO224Ctx

var input224_1: seq[uint8] = hexToBin("1F877C").value
echo "ECHO-224 Input 1 : ", binToHex(input224_1)
echo224Init(ctx224)
echo224Input(ctx224, input224_1)
var output224_1: array[28, uint8] = echo224Final(ctx224)
let hash224_1 = binToHex(output224_1)
echo "ECHO-224 Stream 1 : ", hash224_1
echo "ECHO-224 Standard 1: ED7A2952CBC3068C58FF4C870AB850AFA0A499FE64FB2E943655AB88"
doAssert hash224_1 == "ED7A2952CBC3068C58FF4C870AB850AFA0A499FE64FB2E943655AB88", "ECHO-224 Test 1 Wrong!"

var input224_2: seq[uint8] = hexToBin("FDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFD").value
echo "ECHO-224 Input 2 : ", binToHex(input224_2)
echo224Init(ctx224)
echo224Input(ctx224, input224_2)
var output224_2: array[28, uint8] = echo224Final(ctx224)
let hash224_2 = binToHex(output224_2)
echo "ECHO-224 Stream 2 : ", hash224_2
echo "ECHO-224 Standard 2: 0BE012037ECC300262A12DD01A2298ECBB70620F22CD6B2F15443A89"
doAssert hash224_2 == "0BE012037ECC300262A12DD01A2298ECBB70620F22CD6B2F15443A89", "ECHO-224 Test 2 Wrong!"
echo ""

var ctx256: ECHO256Ctx

var input256_1: seq[uint8] = hexToBin("5BE43C90F22902E4FE8ED2D3").value
echo "ECHO-256 Input 1 : ", binToHex(input256_1)
echo256Init(ctx256)
echo256Input(ctx256, input256_1)
var output256_1: array[32, uint8] = echo256Final(ctx256)
let hash256_1 = binToHex(output256_1)
echo "ECHO-256 Stream 1 : ", hash256_1
echo "ECHO-256 Standard 1: E110E4884E77A1809817D975A30A531B65D5257404E7DE198DD1A2CF8B73B14C"
doAssert hash256_1 == "E110E4884E77A1809817D975A30A531B65D5257404E7DE198DD1A2CF8B73B14C", "ECHO-256 Test 1 Wrong!"

var input256_2: seq[uint8] = hexToBin("FDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFD").value
echo "ECHO-256 Input 2 : ", binToHex(input256_2)
echo256Init(ctx256)
echo256Input(ctx256, input256_2)
var output256_2: array[32, uint8] = echo256Final(ctx256)
let hash256_2 = binToHex(output256_2)
echo "ECHO-256 Stream 2 : ", hash256_2
echo "ECHO-256 Standard 2: 6B8CCFD83C2FC663C9C9ABBC45FABFF1E195D1D3AE96877940DA0E1115BD3AB4"
doAssert hash256_2 == "6B8CCFD83C2FC663C9C9ABBC45FABFF1E195D1D3AE96877940DA0E1115BD3AB4", "ECHO-256 Test 2 Wrong!"
echo ""

var ctx384: ECHO384Ctx

var input384_1: seq[uint8] = hexToBin("1F877C").value
echo "ECHO-384 Input 1 : ", binToHex(input384_1)
echo384Init(ctx384)
echo384Input(ctx384, input384_1)
var output384_1: array[48, uint8] = echo384Final(ctx384)
let hash384_1 = binToHex(output384_1)
echo "ECHO-384 Stream 1 : ", hash384_1
echo "ECHO-384 Standard 1: 91F2A4A29CFEE555751C388AFB63317842E3EF02D7B02FB35ACF3F1CC18366BD37F2B0AEF1F329CF9658E03CCD8FB6C6"
doAssert hash384_1 == "91F2A4A29CFEE555751C388AFB63317842E3EF02D7B02FB35ACF3F1CC18366BD37F2B0AEF1F329CF9658E03CCD8FB6C6", "ECHO-384 Test 1 Wrong!"

var input384_2: seq[uint8] = hexToBin("0DC45181337CA32A8222FE7A3BF42FC9F89744259CFF653504D6051FE84B1A7FFD20CB47D4696CE212A686BB9BE9A8AB1C697B6D6A33").value
echo "ECHO-384 Input 2 : ", binToHex(input384_2)
echo384Init(ctx384)
echo384Input(ctx384, input384_2)
var output384_2: array[48, uint8] = echo384Final(ctx384)
let hash384_2 = binToHex(output384_2)
echo "ECHO-384 Stream 2 : ", hash384_2
echo "ECHO-384 Standard 2: 4608E7610EEC6D3EE68514CA77791E346E187152663E5DD1ED1FA35CF6B4F8839A936FCE428228170E240879D478C084"
doAssert hash384_2 == "4608E7610EEC6D3EE68514CA77791E346E187152663E5DD1ED1FA35CF6B4F8839A936FCE428228170E240879D478C084", "ECHO-384 Test 2 Wrong!"
echo ""

var ctx512: ECHO512Ctx

var input512_1: seq[uint8] = hexToBin("52A608AB21CCDD8A4457A57EDE782176").value
echo "ECHO-512 Input 1 : ", binToHex(input512_1)
echo512Init(ctx512)
echo512Input(ctx512, input512_1)
var output512_1: array[64, uint8] = echo512Final(ctx512)
let hash512_1 = binToHex(output512_1)
echo "ECHO-512 Stream 1 : ", hash512_1
echo "ECHO-512 Standard 1: EA47150919586419ABA6E67E4146FDF7AC285A53E98F9E1E2E949AD5907C2B73E9F36A5DE3687987A85EDCAEC32AF117CB4FD9650E358CC60A43EAAFFC017528"
doAssert hash512_1 == "EA47150919586419ABA6E67E4146FDF7AC285A53E98F9E1E2E949AD5907C2B73E9F36A5DE3687987A85EDCAEC32AF117CB4FD9650E358CC60A43EAAFFC017528", "ECHO-512 Test 1 Wrong!"

var input512_2: seq[uint8] = hexToBin("AECBB02759F7433D6FCB06963C74061CD83B5B3FFA6F13C6").value
echo "ECHO-512 Input 2 : ", binToHex(input512_2)
echo512Init(ctx512)
echo512Input(ctx512, input512_2)
var output512_2: array[64, uint8] = echo512Final(ctx512)
let hash512_2 = binToHex(output512_2)
echo "ECHO-512 Stream 2 : ", hash512_2
echo "ECHO-512 Standard 2: 2D7EC63594F700B2C6DC93069C987E0D85D24EFDDB938249BF084B2F111E979B923CB356EFC2A58C53DC5608E4E26E751CDF00DD81F21D670CA00E05CED341C2"
doAssert hash512_2 == "2D7EC63594F700B2C6DC93069C987E0D85D24EFDDB938249BF084B2F111E979B923CB356EFC2A58C53DC5608E4E26E751CDF00DD81F21D670CA00E05CED341C2", "ECHO-512 Test 2 Wrong!"
echo ""

var res224: array[28, uint8]
var res256: array[32, uint8]
var res384: array[48, uint8]
var res512: array[64, uint8]

benchmark("ECHO-224"):
  for i in 1 .. 1_000_000:
    echo224Init(ctx224)
    echo224Input(ctx224, res224)
    res224 = echo224Final(ctx224)

benchmark("ECHO-256"):
  for i in 1 .. 1_000_000:
    echo256Init(ctx256)
    echo256Input(ctx256, res256)
    res256 = echo256Final(ctx256)

benchmark("ECHO-384"):
  for i in 1 .. 1_000_000:
    echo384Init(ctx384)
    echo384Input(ctx384, res384)
    res384 = echo384Final(ctx384)

benchmark("ECHO-512"):
  for i in 1 .. 1_000_000:
    echo512Init(ctx512)
    echo512Input(ctx512, res512)
    res512 = echo512Final(ctx512)
