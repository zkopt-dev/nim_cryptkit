import "../../src/nim_cryptkit/hash/sha2"
import ../../src/nim_cryptkit/utils/digits
import std/[monotimes, times]

var s: seq[uint8] = charToBin("Hello, World!")

# --- SHA2-224 ---
var ctx224: SHA2_224Ctx
sha2_224Init(ctx224)
sha2_224Input(ctx224, s)
let hash224Stream = binToHex(sha2_224Final(ctx224))
let hash224One = binToHex(sha2_224One(s))
echo "SHA2-224 Stream : ", hash224Stream
echo "SHA2-224 One    : ", hash224One
echo "SHA2-224 Standard: 72A23DFA411BA6FDE01DBFABF3B00A709C93EBF273DC29E2D8B261FF"
doAssert hash224Stream == "72A23DFA411BA6FDE01DBFABF3B00A709C93EBF273DC29E2D8B261FF", "SHA2-224 Stream Wrong! got=" & hash224Stream
doAssert hash224One == "72A23DFA411BA6FDE01DBFABF3B00A709C93EBF273DC29E2D8B261FF", "SHA2-224 One Wrong! got=" & hash224One

# --- SHA2-256 ---
var ctx256: SHA2_256Ctx
sha2_256Init(ctx256)
sha2_256Input(ctx256, s)
let hash256Stream = binToHex(sha2_256Final(ctx256))
let hash256One = binToHex(sha2_256One(s))
echo "SHA2-256 Stream : ", hash256Stream
echo "SHA2-256 One    : ", hash256One
echo "SHA2-256 Standard: DFFD6021BB2BD5B0AF676290809EC3A53191DD81C7F70A4B28688A362182986F"
doAssert hash256Stream == "DFFD6021BB2BD5B0AF676290809EC3A53191DD81C7F70A4B28688A362182986F", "SHA2-256 Stream Wrong! got=" & hash256Stream
doAssert hash256One == "DFFD6021BB2BD5B0AF676290809EC3A53191DD81C7F70A4B28688A362182986F", "SHA2-256 One Wrong! got=" & hash256One

# --- SHA2-384 ---
var ctx384: SHA2_384Ctx
sha2_384Init(ctx384)
sha2_384Input(ctx384, s)
let hash384Stream = binToHex(sha2_384Final(ctx384))
let hash384One = binToHex(sha2_384One(s))
echo "SHA2-384 Stream : ", hash384Stream
echo "SHA2-384 One    : ", hash384One
echo "SHA2-384 Standard: 5485CC9B3365B4305DFB4E8337E0A598A574F8242BF17289E0DD6C20A3CD44A089DE16AB4AB308F63E44B1170EB5F515"
doAssert hash384Stream == "5485CC9B3365B4305DFB4E8337E0A598A574F8242BF17289E0DD6C20A3CD44A089DE16AB4AB308F63E44B1170EB5F515", "SHA2-384 Stream Wrong! got=" & hash384Stream
doAssert hash384One == "5485CC9B3365B4305DFB4E8337E0A598A574F8242BF17289E0DD6C20A3CD44A089DE16AB4AB308F63E44B1170EB5F515", "SHA2-384 One Wrong! got=" & hash384One

# --- SHA2-512 ---
var ctx512: SHA2_512Ctx
sha2_512Init(ctx512)
sha2_512Input(ctx512, s)
let hash512Stream = binToHex(sha2_512Final(ctx512))
let hash512One = binToHex(sha2_512One(s))
echo "SHA2-512 Stream : ", hash512Stream
echo "SHA2-512 One    : ", hash512One
echo "SHA2-512 Standard: 374D794A95CDCFD8B35993185FEF9BA368F160D8DAF432D08BA9F1ED1E5ABE6CC69291E0FA2FE0006A52570EF18C19DEF4E617C33CE52EF0A6E5FBE318CB0387"
doAssert hash512Stream == "374D794A95CDCFD8B35993185FEF9BA368F160D8DAF432D08BA9F1ED1E5ABE6CC69291E0FA2FE0006A52570EF18C19DEF4E617C33CE52EF0A6E5FBE318CB0387", "SHA2-512 Stream Wrong! got=" & hash512Stream
doAssert hash512One == "374D794A95CDCFD8B35993185FEF9BA368F160D8DAF432D08BA9F1ED1E5ABE6CC69291E0FA2FE0006A52570EF18C19DEF4E617C33CE52EF0A6E5FBE318CB0387", "SHA2-512 One Wrong! got=" & hash512One

# --- SHA2-512/224 ---
var ctx512_224: SHA2_512_224Ctx
sha2_512_224Init(ctx512_224)
sha2_512_224Input(ctx512_224, s)
let hash512_224Stream = binToHex(sha2_512_224Final(ctx512_224))
let hash512_224One = binToHex(sha2_512_224One(s))
echo "SHA2-512/224 Stream : ", hash512_224Stream
echo "SHA2-512/224 One    : ", hash512_224One
echo "SHA2-512/224 Standard: 766745F058E8A0438F19DE48AE56EA5F123FE738AF39BCA050A7547A"
doAssert hash512_224Stream == "766745F058E8A0438F19DE48AE56EA5F123FE738AF39BCA050A7547A", "SHA2-512/224 Stream Wrong! got=" & hash512_224Stream
doAssert hash512_224One == "766745F058E8A0438F19DE48AE56EA5F123FE738AF39BCA050A7547A", "SHA2-512/224 One Wrong! got=" & hash512_224One

# --- SHA2-512/256 ---
var ctx512_256: SHA2_512_256Ctx
sha2_512_256Init(ctx512_256)
sha2_512_256Input(ctx512_256, s)
let hash512_256Stream = binToHex(sha2_512_256Final(ctx512_256))
let hash512_256One = binToHex(sha2_512_256One(s))
echo "SHA2-512/256 Stream : ", hash512_256Stream
echo "SHA2-512/256 One    : ", hash512_256One
echo "SHA2-512/256 Standard: 0686F0A605973DC1BF035D1E2B9BAD1985A0BFF712DDD88ABD8D2593E5F99030"
doAssert hash512_256Stream == "0686F0A605973DC1BF035D1E2B9BAD1985A0BFF712DDD88ABD8D2593E5F99030", "SHA2-512/256 Stream Wrong! got=" & hash512_256Stream
doAssert hash512_256One == "0686F0A605973DC1BF035D1E2B9BAD1985A0BFF712DDD88ABD8D2593E5F99030", "SHA2-512/256 One Wrong! got=" & hash512_256One

# --- Benchmark ---
template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

var temp224: array[28, uint8]
var temp256: array[32, uint8]
var temp384: array[48, uint8]
var temp512: array[64, uint8]
var temp512_224: array[28, uint8]
var temp512_256: array[32, uint8]

benchmark("SHA2-224 Benchmark"):
  for i in 1 .. 1_000_000:
    sha2_224Init(ctx224)
    sha2_224Input(ctx224, temp224)
    temp224 = sha2_224Final(ctx224)

benchmark("SHA2-256 Benchmark"):
  for i in 1 .. 1_000_000:
    sha2_256Init(ctx256)
    sha2_256Input(ctx256, temp256)
    temp256 = sha2_256Final(ctx256)

benchmark("SHA2-384 Benchmark"):
  for i in 1 .. 1_000_000:
    sha2_384Init(ctx384)
    sha2_384Input(ctx384, temp384)
    temp384 = sha2_384Final(ctx384)

benchmark("SHA2-512 Benchmark"):
  for i in 1 .. 1_000_000:
    sha2_512Init(ctx512)
    sha2_512Input(ctx512, temp512)
    temp512 = sha2_512Final(ctx512)

benchmark("SHA2-512/224 Benchmark"):
  for i in 1 .. 1_000_000:
    sha2_512_224Init(ctx512_224)
    sha2_512_224Input(ctx512_224, temp512_224)
    temp512_224 = sha2_512_224Final(ctx512_224)

benchmark("SHA2-512/256 Benchmark"):
  for i in 1 .. 1_000_000:
    sha2_512_256Init(ctx512_256)
    sha2_512_256Input(ctx512_256, temp512_256)
    temp512_256 = sha2_512_256Final(ctx512_256)
