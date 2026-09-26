import ../utils/endian
import ../utils/digits
import ../utils/bitutils
import ../utils/envconst
import ../utils/slicearray
import ../utils/optmacro
import ../utils/errorutils
import std/[monotimes, times]
import std/bitops
import strutils

const
  SkeinC240 = 0x1BD11BDAA9FC1A22'u64
  SkeinFirst = 1'u64 shl 62
  SkeinFinal = 1'u64 shl 63
  SkeinKey = 0'u64
  SkeinConfig = 4'u64
  SkeinPersonal = 8'u64
  SkeinPublicKey = 12'u64
  SkeinKeyId = 16'u64
  SkeinNonce = 20'u64
  SkeinMessage = 48'u64
  SkeinOutput = 63'u64
  SkeinSchemaId = 0x0000000133414853'u64

  SKEIN512_IV160: array[8, uint64] = [
    0x28B81A2AE013BD91'u64, 0xC2F11668B5BDF78F'u64,
    0x1760D8F3F6A56F12'u64, 0x4FB747588239904F'u64,
    0x21EDE07F7EAF5056'u64, 0xD908922E63ED70B8'u64,
    0xB8EC76FFECCB52FA'u64, 0x01A47BB8A3F27A6E'u64
  ]
  SKEIN512_IV224: array[8, uint64] = [
    0xCCD0616248677224'u64, 0xCBA65CF3A92339EF'u64,
    0x8CCD69D652FF4B64'u64, 0x398AED7B3AB890B4'u64,
    0x0F59D1B1457D2BD0'u64, 0x6776FE6575D4EB3D'u64,
    0x99FBC70E997413E9'u64, 0x9E2CFCCFE1C41EF7'u64
  ]
  SKEIN512_IV256: array[8, uint64] = [
    0xCCD044A12FDB3E13'u64, 0xE83590301A79A9EB'u64,
    0x55AEA0614F816E6F'u64, 0x2A2767A4AE9B94DB'u64,
    0xEC06025E74DD7683'u64, 0xE7A436CDC4746251'u64,
    0xC36FBAF9393AD185'u64, 0x3EEDBA1833EDFC13'u64
  ]
  SKEIN512_IV384: array[8, uint64] = [
    0xA3F6C6BF3A75EF5F'u64, 0xB0FEF9CCFD84FAA4'u64,
    0x9D77DD663D770CFE'u64, 0xD798CBF3B468FDDA'u64,
    0x1BC4A6668A0E4465'u64, 0x7ED7D434E5807407'u64,
    0x548FC1ACD4EC44D6'u64, 0x266E17546AA18FF8'u64
  ]
  SKEIN512_IV512: array[8, uint64] = [
    0x4903ADFF749C51CE'u64, 0x0D95DE399746DF03'u64,
    0x8FD1934127C79BCE'u64, 0x9A255629FF352CB1'u64,
    0x5DB62599DF6CA7B0'u64, 0xEABE394CA9D5C3F4'u64,
    0x991112C71A75B523'u64, 0xAE18A40B660FCC33'u64
  ]

  SKEIN_ROT_512 = [
    [46, 36, 19, 37],
    [33, 27, 14, 42],
    [17, 49, 36, 39],
    [44, 9, 54, 56],
    [39, 30, 34, 24],
    [13, 50, 10, 17],
    [25, 29, 39, 43],
    [8, 35, 56, 22]
  ]
  SKEIN_PAIR_512 = [
    [0, 1, 2, 3, 4, 5, 6, 7],
    [2, 1, 4, 7, 6, 5, 0, 3],
    [4, 1, 6, 3, 0, 5, 2, 7],
    [6, 1, 0, 7, 2, 5, 4, 3]
  ]

type
  Skein512Ctx*[hashSize: static int, blockSize: static int] = object
    chain*: array[8, uint64]
    tweak*: array[2, uint64]
    buffer*: array[64, uint8]
    index*: int

  Skein512_160Ctx* = Skein512Ctx[20, 64]
  Skein512_224Ctx* = Skein512Ctx[28, 64]
  Skein512_256Ctx* = Skein512Ctx[32, 64]
  Skein512_384Ctx* = Skein512Ctx[48, 64]
  Skein512_512Ctx* = Skein512Ctx[64, 64]

template skeinInject(x: var array[8, uint64], key: array[9, uint64], tweak: array[3, uint64], s: int) =
  x[0] = x[0] + key[(s + 0) mod 9]
  x[1] = x[1] + key[(s + 1) mod 9]
  x[2] = x[2] + key[(s + 2) mod 9]
  x[3] = x[3] + key[(s + 3) mod 9]
  x[4] = x[4] + key[(s + 4) mod 9]
  x[5] = x[5] + key[(s + 5) mod 9] + tweak[s mod 3]
  x[6] = x[6] + key[(s + 6) mod 9] + tweak[(s + 1) mod 3]
  x[7] = x[7] + key[(s + 7) mod 9] + uint64(s)

template skeinMix(x: var array[8, uint64], a, b: int, r: static int): void =
  x[a] = x[a] + x[b]
  x[b] = rotateLeftBits(x[b], r) xor x[a]

template skeinThreefish512(chain: array[8, uint64], tweakIn: array[2, uint64], input: array[8, uint64]): array[8, uint64] =
  var key: array[9, uint64]
  copyMem(addr key[0], addr chain[0], 64)

  key[8] = SkeinC240 xor key[0] xor key[1] xor key[2] xor key[3] xor
                         key[4] xor key[5] xor key[6] xor key[7]

  var tweak: array[3, uint64]
  tweak[0] = tweakIn[0]
  tweak[1] = tweakIn[1]
  tweak[2] = tweak[0] xor tweak[1]

  var x = input
  unroll(d, 0, 72 - 1):
    when (d mod 4) == 0:
      skeinInject(x, key, tweak, d div 4)

    unroll(p, 0, 3):
      skeinMix(x, SKEIN_PAIR_512[d mod 4][p * 2 + 0], SKEIN_PAIR_512[d mod 4][p * 2 + 1], SKEIN_ROT_512[d mod 8][p])
  skeinInject(x, key, tweak, 18)
  var output: array[8, uint64] = x
  output

template skeinBlock(chain: var array[8, uint64], tweak: array[2, uint64], input: array[8, uint64]): void =
  let encrypt: array[8, uint64] = skeinThreefish512(chain, tweak, input)
  for i in static(0 ..< 8):
    chain[i] = encrypt[i] xor input[i]

template skein512Transform(chain: var array[8, uint64], tweak: var array[2, uint64], chunk: slicearray[64, uint8], count: int = 64): void =
  tweak[0] = tweak[0] + uint64(count)
  var words: array[8, uint64]
  decodeLE(chunk, words.toSliceArray(0, 7))
  skeinBlock(chain, tweak, words)
  tweak[1] = tweak[1] and not SkeinFirst

template skein512InitC[K, B: static int](ctx: var Skein512Ctx[K, B]): void =
  when K == 20:
    ctx.chain = SKEIN512_IV160
  elif K == 28:
    ctx.chain = SKEIN512_IV224
  elif K == 32:
    ctx.chain = SKEIN512_IV256
  elif K == 48:
    ctx.chain = SKEIN512_IV384
  elif K == 64:
    ctx.chain = SKEIN512_IV512
  ctx.tweak[0] = 0'u64
  ctx.tweak[1] = (SkeinMessage shl 56) or SkeinFirst
  zeroMem(addr ctx.buffer, 64)
  ctx.index = 0

template skein512InputC[K, B: static int](ctx: var Skein512Ctx[K, B], input: openArray[uint8]): void =
  let inputLen: int = input.len

  var check: bool = true

  if inputLen <= 0: check = false

  if check:
    var index: int = ctx.index
    let left: int = 64 - index
    var position: int = 0

    if inputLen > left:
      if left > 0:
        copyMem(addr ctx.buffer[index], addr input[0], left)
      skein512Transform(ctx.chain, ctx.tweak, ctx.buffer.toSliceArray(0, 63))
      position = left
      index = 0

      while position + 64 < inputLen:
        skein512Transform(ctx.chain, ctx.tweak, input.toSliceArray(position, position + 63, 64))
        position += 64

    let remain: int = inputLen - position
    if remain > 0:
      copyMem(addr ctx.buffer[index], addr input[position], remain)
      index += remain

    ctx.index = index

template skein512FinalC[K, B: static int](ctx: var Skein512Ctx[K, B]): array[K, uint8] =
  var index: int = ctx.index
  if index < 64:
    zeroMem(addr ctx.buffer[index], 64 - index)
  ctx.tweak[1] = ctx.tweak[1] or SkeinFinal

  skein512Transform(ctx.chain, ctx.tweak, ctx.buffer.toSliceArray(0, 63), index)

  var output: array[K, uint8]

  var written: int = 0
  var counter: uint64 = 0'u64

  var words: array[8, uint64]
  var tweak: array[2, uint64]
  while written < K:
    zeroMem(addr words[0], 64)
    words[0] = counter
    tweak[0] = 8'u64
    tweak[1] = (SkeinOutput shl 56) or SkeinFirst or SkeinFinal

    var temp: array[8, uint64] = ctx.chain
    skeinBlock(temp, tweak, words)

    let take: int = min(64, K - written)
    for i in 0 ..< take:
      output[written + i] = uint8((temp[i div 8] shr ((i mod 8) * 8)) and 0xFF'u64)

    written += take
    counter.inc

  output
#[
type
  Skein512Config* = object
    key*: seq[uint8]
    personal*: seq[uint8]
    publicKey*: seq[uint8]
    keyId*: seq[uint8]
    nonce*: seq[uint8]

proc skein512InitConfigImpl[K, B: static int](ctx: var Skein512Ctx[K, B],
    conf: Skein512Config) =
  ctx.chain = default(array[8, uint64])
  ctx.initialChain = default(array[8, uint64])
  ctx.outputLen = uint64(K)

  if conf.key.len > 0:
    skein512ProcessParam(ctx, SkeinKey, conf.key)

  var cfg: array[32, uint8]
  skeinStore64Le(cfg, 0, SkeinSchemaId)
  skeinStore64Le(cfg, 8, uint64(K * 8))
  skein512ProcessParam(ctx, SkeinConfig, cfg)

  if conf.personal.len > 0:
    skein512ProcessParam(ctx, SkeinPersonal, conf.personal)
  if conf.publicKey.len > 0:
    skein512ProcessParam(ctx, SkeinPublicKey, conf.publicKey)
  if conf.keyId.len > 0:
    skein512ProcessParam(ctx, SkeinKeyId, conf.keyId)
  if conf.nonce.len > 0:
    skein512ProcessParam(ctx, SkeinNonce, conf.nonce)

  ctx.initialChain = ctx.chain
  skein512ResetMessage(ctx)

proc skein512DigestConfigImpl[K: static int](input: openArray[uint8],
    conf: Skein512Config): array[K, uint8] =
  var ctx: Skein512Ctx[K, 64]
  skein512InitConfigImpl(ctx, conf)
  skein512InputImpl(ctx, input)
  result = skein512FinalImpl(ctx)

proc skein512DigestWithKeyImpl[K: static int](input,
    key: openArray[uint8]): array[K, uint8] =
  var conf: Skein512Config
  conf.key = @key
  result = skein512DigestConfigImpl[K](input, conf)
]#

## SKEIN-256 UNSUPPORTED
#[
const
  ROTATE256: array[8, array[2, int]]= [
    [14, 16], [52, 57], [23, 40], [5, 37],
    [25, 33], [46, 12], [58, 22], [32, 32]
  ]

type
  Skeins256Ctx*[hashSize: static int, blockSize: static int] = object
    state*: array[4, uint64]
    buffer*: array[blockSize, uint8]
    index*: int
    blocks*: uint64

template skeinsMix(a, b: var uint64, rot: static int) =
  a += b
  b = rotateLeftBits(b, rot) xor a

template skeinsTransform256[K, B: static int](ctx: var Skeins256Ctx[K, B], chunk: slicearray[32, uint8], etype, extra: int) =
  var m: array[4, uint64]

  decodeLE(chunk, m.toSliceArray(0, 3))

  var h: array[5, uint64]
  copyMem(addr h[0], addr state[0], 32)
  h[4] = h[0] xor h[1] xor h[2] xor h[3] xor C240

  let tweak0 = (ctx.blocks shl 5) + uint64(extra)
  let tweak1 = (ctx.blocks shr 59) + (uint64(etype) shl 55)
  let tweak: array[3, uint64] = [tweak0, tweak1, tweak0 xor tweak1]

  var p = m
  p[0] += h[0]
  p[1] += h[1] + tweak[0]
  p[2] += h[2] + tweak[1]
  p[3] += h[3]

  template rounds(s, r: static int): void =
    const rotate = ROTATE256[(s * 4 + r) mod 8]
    skeinsMix(p[0], p[1], rotate[0])
    skeinsMix(p[0], p[1], rotate[1])


  unroll(s, 0, 18 - 1):
    unroll(r, 0, 3):
      rounds(s, r)
    p[0] += h[(s + 1) mod 5]
    p[1] += h[(s + 2) mod 5] + t[(s + 1) mod 3]
    p[2] += h[(s + 3) mod 5] + t[(s + 2) mod 3]
    p[3] += h[(s + 4) mod 5] + uint64(s + 1)

  for i in 0 ..< 4:
    ctx.state[i] = m[i] xor p[i]

template skeins256InitC[K, B: static int](ctx: var Skeins256Ctx[K, B], iv: array[4, uint64]) =
  ctx.state = iv
  zeroMem(addr ctx.buffer, B)
  ctx.index = 0
  ctx.blocks = 0

template skeins256InputC[K, B: static int](ctx: var Skeins256Ctx[K, B], input: openArray[uint8]) =
  var check: bool = true
  let inputLen: int = input.len

  if inputLen <= 0: check = false

  if check:
    var index: int = ctx.index

    let left: int = 32 - index
    var position: int = 0

    if inputLen >= left:
      if left > 0:
        copyMem(addr ctx.buffer[index], addr input[position], left)
      var etype: int = if ctx.blocks == 0'u64: 224 else: 96
      ctx.blocks.inc
      skeinsTransform256(ctx, ctx.buffer.toSliceArray(0, 31), etype, 0)

      while position + 32 <= inputLen:
        if left > 0:
          copyMem(addr ctx.buffer[index], addr input[position], left)
        etype = if ctx.blocks == 0'u64: 224 else: 96
        ctx.blocks.inc
        skeinsTransform256(ctx, input.toSliceArray(position, position + 31, 32), etype, 0)
        position += 32

    let remain: int = inputLen - position
    if remain > 0:
      copyMem(addr ctx.buffer[index], addr input[position], remain)
      index += remain

    ctx.index = index

template skeins256FinalC[K, B: static int](ctx: var Skeins256Ctx[K, B]): array[K, uint8] =
  var output: array[K, uint8]
  var index: int = ctx.index

  zeroMem(addr ctx.buffer[index], B - index)
  let etype: int = if ctx.blocks == 0'u64: 480 else: 352
  skeinsTransform256(ctx, etype, index)

  zeroMem(addr ctx.buffer, B)
  ctx.blocks = 0
  skeinsTransform256(ctx,510, 8)

  var temp: array[32, uint8]
  encodeLE(ctx.state, temp)

  copyMem(addr output[0], addr temp[0], K)

  output
]#
# export wrappers
when defined(templateOpt):
  template skein512_160Init*(ctx: var Skein512_160Ctx): void = skein512InitC(ctx)
  template skein512_160Input*(ctx: var Skein512_160Ctx, input: openArray[uint8]): void = skein512InputC(ctx, input)
  template skein512_160Final*(ctx: var Skein512_160Ctx): array[20, uint8] = skein512FinalC(ctx)

  template skein512_224Init*(ctx: var Skein512_224Ctx): void = skein512InitC(ctx)
  template skein512_224Input*(ctx: var Skein512_224Ctx, input: openArray[uint8]): void = skein512InputC(ctx, input)
  template skein512_224Final*(ctx: var Skein512_224Ctx): array[28, uint8] = skein512FinalC(ctx)

  template skein512_256Init*(ctx: var Skein512_256Ctx): void = skein512InitC(ctx)
  template skein512_256Input*(ctx: var Skein512_256Ctx, input: openArray[uint8]): void = skein512InputC(ctx, input)
  template skein512_256Final*(ctx: var Skein512_256Ctx): array[32, uint8] = skein512FinalC(ctx)

  template skein512_384Init*(ctx: var Skein512_384Ctx): void = skein512InitC(ctx)
  template skein512_384Input*(ctx: var Skein512_384Ctx, input: openArray[uint8]): void = skein512InputC(ctx, input)
  template skein512_384Final*(ctx: var Skein512_384Ctx): array[48, uint8] = skein512FinalC(ctx)

  template skein512Init*(ctx: var Skein512_512Ctx): void = skein512InitC(ctx)
  template skein512Input*(ctx: var Skein512_512Ctx, input: openArray[uint8]): void = skein512InputC(ctx, input)
  template skein512Final*(ctx: var Skein512_512Ctx): array[64, uint8] = skein512FinalC(ctx)

  when Native:
    template skein512_160Init*(ctx: ptr Skein512_160Ctx): void = skein512InitC(ctx[])
    template skein512_160Input*(ctx: ptr Skein512_160Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = skein512InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template skein512_160Final*(ctx: ptr Skein512_160Ctx, output: ptr array[20, uint8]): void = output[] = skein512FinalC(ctx[])

    template skein512_224Init*(ctx: ptr Skein512_224Ctx): void = skein512InitC(ctx[])
    template skein512_224Input*(ctx: ptr Skein512_224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = skein512InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template skein512_224Final*(ctx: ptr Skein512_224Ctx, output: ptr array[28, uint8]): void = output[] = skein512FinalC(ctx[])

    template skein512_256Init*(ctx: ptr Skein512_256Ctx): void = skein512InitC(ctx[])
    template skein512_256Input*(ctx: ptr Skein512_256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = skein512InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template skein512_256Final*(ctx: ptr Skein512_256Ctx, output: ptr array[32, uint8]): void = output[] = skein512FinalC(ctx[])

    template skein512_384Init*(ctx: ptr Skein512_384Ctx): void = skein512InitC(ctx[])
    template skein512_384Input*(ctx: ptr Skein512_384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = skein512InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template skein512_384Final*(ctx: ptr Skein512_384Ctx, output: ptr array[48, uint8]): void = output[] = skein512FinalC(ctx[])

    template skein512Init*(ctx: ptr Skein512_512Ctx): void = skein512InitC(ctx[])
    template skein512Input*(ctx: ptr Skein512_512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = skein512InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template skein512Final*(ctx: ptr Skein512_512Ctx, output: ptr array[64, uint8]): void = output[] = skein512FinalC(ctx[])

else:
  when Native:
    proc skein512_160Init*(ctx: var Skein512_160Ctx): void = skein512InitC(ctx)
    proc skein512_160Input*(ctx: var Skein512_160Ctx, input: openArray[uint8]): void = skein512InputC(ctx, input)
    proc skein512_160Final*(ctx: var Skein512_160Ctx): array[20, uint8] = skein512FinalC(ctx)

    proc skein512_224Init*(ctx: var Skein512_224Ctx): void = skein512InitC(ctx)
    proc skein512_224Input*(ctx: var Skein512_224Ctx, input: openArray[uint8]): void = skein512InputC(ctx, input)
    proc skein512_224Final*(ctx: var Skein512_224Ctx): array[28, uint8] = skein512FinalC(ctx)

    proc skein512_256Init*(ctx: var Skein512_256Ctx): void = skein512InitC(ctx)
    proc skein512_256Input*(ctx: var Skein512_256Ctx, input: openArray[uint8]): void = skein512InputC(ctx, input)
    proc skein512_256Final*(ctx: var Skein512_256Ctx): array[32, uint8] = skein512FinalC(ctx)

    proc skein512_384Init*(ctx: var Skein512_384Ctx): void = skein512InitC(ctx)
    proc skein512_384Input*(ctx: var Skein512_384Ctx, input: openArray[uint8]): void = skein512InputC(ctx, input)
    proc skein512_384Final*(ctx: var Skein512_384Ctx): array[48, uint8] = skein512FinalC(ctx)

    proc skein512Init*(ctx: var Skein512_512Ctx): void = skein512InitC(ctx)
    proc skein512Input*(ctx: var Skein512_512Ctx, input: openArray[uint8]): void = skein512InputC(ctx, input)
    proc skein512Final*(ctx: var Skein512_512Ctx): array[64, uint8] = skein512FinalC(ctx)

  when defined(c) or defined(objc):
    proc skein512_160Init*(ctx: ptr Skein512_160Ctx): void {.exportc: "skein512_160Init".} = skein512InitC(ctx[])
    proc skein512_160Input*(ctx: ptr Skein512_160Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "skein512_160Input".} = skein512InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc skein512_160Final*(ctx: ptr Skein512_160Ctx, output: ptr array[20, uint8]): void {.exportc: "skein512_160Final".} = output[] = skein512FinalC(ctx[])

    proc skein512_224Init*(ctx: ptr Skein512_224Ctx): void {.exportc: "skein512_224Init".} = skein512InitC(ctx[])
    proc skein512_224Input*(ctx: ptr Skein512_224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "skein512_224Input".} = skein512InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc skein512_224Final*(ctx: ptr Skein512_224Ctx, output: ptr array[28, uint8]): void {.exportc: "skein512_224Final".} = output[] = skein512FinalC(ctx[])

    proc skein512_256Init*(ctx: ptr Skein512_256Ctx): void {.exportc: "skein512_256Init".} = skein512InitC(ctx[])
    proc skein512_256Input*(ctx: ptr Skein512_256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "skein512_256Input".} = skein512InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc skein512_256Final*(ctx: ptr Skein512_256Ctx, output: ptr array[32, uint8]): void {.exportc: "skein512_256Final".} = output[] = skein512FinalC(ctx[])

    proc skein512_384Init*(ctx: ptr Skein512_384Ctx): void {.exportc: "skein512_384Init".} = skein512InitC(ctx[])
    proc skein512_384Input*(ctx: ptr Skein512_384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "skein512_384Input".} = skein512InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc skein512_384Final*(ctx: ptr Skein512_384Ctx, output: ptr array[48, uint8]): void {.exportc: "skein512_384Final".} = output[] = skein512FinalC(ctx[])

    proc skein512Init*(ctx: ptr Skein512_512Ctx): void {.exportc: "skein512Init".} = skein512InitC(ctx[])
    proc skein512Input*(ctx: ptr Skein512_512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "skein512Input".} = skein512InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc skein512Final*(ctx: ptr Skein512_512Ctx, output: ptr array[64, uint8]): void {.exportc: "skein512Final".} = output[] = skein512FinalC(ctx[])

  elif defined(cpp):
    proc skein512_160Init*(ctx: ptr Skein512_160Ctx): void {.exportcpp: "skein512_160Init".} = skein512InitC(ctx[])
    proc skein512_160Input*(ctx: ptr Skein512_160Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "skein512_160Input".} = skein512InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc skein512_160Final*(ctx: ptr Skein512_160Ctx, output: ptr array[20, uint8]): void {.exportcpp: "skein512_160Final".} = output[] = skein512FinalC(ctx[])

    proc skein512_224Init*(ctx: ptr Skein512_224Ctx): void {.exportcpp: "skein512_224Init".} = skein512InitC(ctx[])
    proc skein512_224Input*(ctx: ptr Skein512_224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "skein512_224Input".} = skein512InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc skein512_224Final*(ctx: ptr Skein512_224Ctx, output: ptr array[28, uint8]): void {.exportcpp: "skein512_224Final".} = output[] = skein512FinalC(ctx[])

    proc skein512_256Init*(ctx: ptr Skein512_256Ctx): void {.exportcpp: "skein512_256Init".} = skein512InitC(ctx[])
    proc skein512_256Input*(ctx: ptr Skein512_256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "skein512_256Input".} = skein512InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc skein512_256Final*(ctx: ptr Skein512_256Ctx, output: ptr array[32, uint8]): void {.exportcpp: "skein512_256Final".} = output[] = skein512FinalC(ctx[])

    proc skein512_384Init*(ctx: ptr Skein512_384Ctx): void {.exportcpp: "skein512_384Init".} = skein512InitC(ctx[])
    proc skein512_384Input*(ctx: ptr Skein512_384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "skein512_384Input".} = skein512InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc skein512_384Final*(ctx: ptr Skein512_384Ctx, output: ptr array[48, uint8]): void {.exportcpp: "skein512_384Final".} = output[] = skein512FinalC(ctx[])

    proc skein512Init*(ctx: ptr Skein512_512Ctx): void {.exportcpp: "skein512Init".} = skein512InitC(ctx[])
    proc skein512Input*(ctx: ptr Skein512_512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "skein512Input".} = skein512InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc skein512Final*(ctx: ptr Skein512_512Ctx, output: ptr array[64, uint8]): void {.exportcpp: "skein512Final".} = output[] = skein512FinalC(ctx[])
