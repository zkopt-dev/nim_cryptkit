import ../utils/vectorop
import ../utils/bitutils
import ../utils/endian
import ../utils/errorutils
import ../utils/digits
import ../utils/slicearray
import ../utils/optmacro
import ../utils/envconst
import ../utils/biguintBE
import helper
import ../hash/sha2
import pbkdf2

type
  YescryptMode* = enum
    yescryptClassic, yescryptWorm, yescryptRw

  YescryptCtx* = object
    mode*: YescryptMode
    n*, r*, p*, t*: int

  PwxCtx = object
    s0, s1, s2: seq[uint32]
    w: int

const
  PwxSimple = 2
  PwxGather = 4
  PwxRounds = 6
  SWidth = 8
  PwxWords = 16
  SMask = ((1 shl SWidth) - 1) * PwxSimple * 8
  SWords = 3 * (1 shl SWidth) * PwxSimple * 2

template wordsToBytes(input: openArray[uint32]): seq[uint8] =
  var output: seq[uint8] = newSeq[uint8](input.len * 4)
  encodeLE(input, output)
  output

template bytesToWords(input: openArray[byte]): seq[uint32] =
  var output: seq[uint32] = newSeq[uint32](input.len div 4)
  decodeLE(input, output)
  output

template yescryptInit*(mode: YescryptMode = yescryptRw, n = 4096, r = 32, p = 1, t = 0): YescryptCtx =
  YescryptCtx(mode: mode, n: n, r: r, p: p, t: t)

template salsaInternal(input: array[16, uint32], doubleRounds: int): void =
  var original, x: array[16, uint32]
  for i in static(0 ..< 16):
    original[i * 5 mod 16] = input[i]
    x[i * 5 mod 16] = input[i]
  for _ in 0 ..< doubleRounds:
    x[4] = x[4] xor rotateLeftBits(x[0] + x[12], 7)
    x[8] = x[8] xor rotateLeftBits(x[4] + x[0], 9)
    x[12] = x[12] xor rotateLeftBits(x[8] + x[4], 13)
    x[0] = x[0] xor rotateLeftBits(x[12] + x[8], 18)
    x[9] = x[9] xor rotateLeftBits(x[5] + x[1], 7)
    x[13] = x[13] xor rotateLeftBits(x[9] + x[5], 9)
    x[1] = x[1] xor rotateLeftBits(x[13] + x[9], 13)
    x[5] = x[5] xor rotateLeftBits(x[1] + x[13], 18)
    x[14] = x[14] xor rotateLeftBits(x[10] + x[6], 7)
    x[2] = x[2] xor rotateLeftBits(x[14] + x[10], 9)
    x[6] = x[6] xor rotateLeftBits(x[2] + x[14], 13)
    x[10] = x[10] xor rotateLeftBits(x[6] + x[2], 18)
    x[3] = x[3] xor rotateLeftBits(x[15] + x[11], 7)
    x[7] = x[7] xor rotateLeftBits(x[3] + x[15], 9)
    x[11] = x[11] xor rotateLeftBits(x[7] + x[3], 13)
    x[15] = x[15] xor rotateLeftBits(x[11] + x[7], 18)
    x[1] = x[1] xor rotateLeftBits(x[0] + x[3], 7)
    x[2] = x[2] xor rotateLeftBits(x[1] + x[0], 9)
    x[3] = x[3] xor rotateLeftBits(x[2] + x[1], 13)
    x[0] = x[0] xor rotateLeftBits(x[3] + x[2], 18)
    x[6] = x[6] xor rotateLeftBits(x[5] + x[4], 7)
    x[7] = x[7] xor rotateLeftBits(x[6] + x[5], 9)
    x[4] = x[4] xor rotateLeftBits(x[7] + x[6], 13)
    x[5] = x[5] xor rotateLeftBits(x[4] + x[7], 18)
    x[11] = x[11] xor rotateLeftBits(x[10] + x[9], 7)
    x[8] = x[8] xor rotateLeftBits(x[11] + x[10], 9)
    x[9] = x[9] xor rotateLeftBits(x[8] + x[11], 13)
    x[10] = x[10] xor rotateLeftBits(x[9] + x[8], 18)
    x[12] = x[12] xor rotateLeftBits(x[15] + x[14], 7)
    x[13] = x[13] xor rotateLeftBits(x[12] + x[15], 9)
    x[14] = x[14] xor rotateLeftBits(x[13] + x[12], 13)
    x[15] = x[15] xor rotateLeftBits(x[14] + x[13], 18)
  for i in static(0 ..< 16):
    input[i] = original[i * 5 mod 16] + x[i * 5 mod 16]

template blockmixSalsa8(x, y: var seq[uint32]; r: int) =
  var state: array[16, uint32]
  for j in static(0 ..< 16):
    state[j] = x[(2 * r - 1) * 16 + j]

  for i in 0 ..< (2 * r):
    for j in static(0 ..< 16):
      state[j] = state[j] xor x[i * 16 + j]
    salsaInternal(state, 4)

    copyMem(addr y[i * 16], addr state[0], 64)

  for i in 0 ..< r:
    for j in static(0 ..< 16):
      x[i * 16 + j] = y[(i * 2) * 16 + j]
      x[(i + r) * 16 + j] = y[(i * 2 + 1) * 16 + j]

template pwxform(ctx: var PwxCtx, state: var openArray[uint32]): void =
  var w = ctx.w
  for round in 0..<PwxRounds:
    for gather in 0..<PwxGather:
      let base = gather * 4
      # Both simple lanes in a gather use lookup positions selected by
      # the first lane, as specified by pwxform.
      let p0 = (int(state[base]) and SMask) div 8
      let p1 = (int(state[base+1]) and SMask) div 8
      for simple in 0..<PwxSimple:
        let offset: int = base + simple * 2
        let xl = state[offset]
        let xh = state[offset + 1]
        let s0 = uint64(ctx.s0[(p0+simple)*2]) or
                 (uint64(ctx.s0[(p0+simple)*2+1]) shl 32)
        let s1 = uint64(ctx.s1[(p1+simple)*2]) or
                 (uint64(ctx.s1[(p1+simple)*2+1]) shl 32)
        var value = uint64(xh) * uint64(xl)
        value = (value + s0) xor s1
        state[offset] = uint32(value)
        state[offset + 1] = uint32(value shr 32)
        if round != 0 and round != PwxRounds-1:
          ctx.s2[w*2] = uint32(value)
          ctx.s2[w*2+1] = uint32(value shr 32)
          inc w
  swap(ctx.s0, ctx.s2)
  swap(ctx.s1, ctx.s2)
  ctx.w = w and ((1 shl SWidth) * PwxSimple - 1)

template blockmixPwx(ctx: var PwxCtx; x: var seq[uint32]; r: int) =
  let chunks: int = 2*r
  var state: array[PwxWords, uint32]

  copyMem(addr state[0], addr x[(chunks - 1) * PwxWords], PwxWords * 4)

  for i in 0 ..< chunks:
    for j in static(0 ..< PwxWords):
      state[j] = state[j] xor x[i * PwxWords + j]
    pwxform(ctx, state)

    copyMem(addr x[i * PwxWords], addr state[0], PwxWords * 4)

    copyMem(addr x[i * PwxWords], addr state[0], PwxWords * 4)

  var last: array[16, uint32]
  copyMem(addr last[0], addr x[(chunks - 1) * 16], 64)
  salsaInternal(last, 1)
  copyMem(addr x[(chunks - 1) * 16], addr last[0], 64)

template integerify(x: openArray[uint32]; r: int): uint64 =
  let offset: int = (2 * r - 1) * 16
  uint64(x[offset]) + (uint64(x[offset + 13]) shl 32)

template prevPowerOfTwo(x: int): int =
  var output: int = x
  while (output and (output - 1)) != 0:
    output = output and (output - 1)
  output

template smix1(b: var seq[uint32], bOffset, r, n: int, mode: YescryptMode,
               v: var seq[uint32], vOffset: int, xy: var seq[uint32],
               ctx: var PwxCtx, haveCtx: bool): void =
  let s: int = 32 * r
  var x: seq[uint32] = newSeq[uint32](s)
  var y: seq[uint32] = newSeq[uint32](s)
  for k in 0 ..< (2 * r):
    for i in static(0 ..< 16):
      x[k * 16 + i] = b[bOffset + k * 16 + (i*5 mod 16)]
  for i in 0 ..< n:
    for k in 0 ..< s:
      v[vOffset + i * s + k] = x[k
                                 ]
    if mode == yescryptRw and i > 1:
      let power = prevPowerOfTwo(i)
      let j: int = int(integerify(x, r) and uint64(power-1)) + i-power
      for k in 0 ..< s:
        x[k] = x[k] xor v[vOffset + j * s + k]

    if haveCtx:
      blockmixPwx(ctx, x, r)
    else:
      blockmixSalsa8(x, y, r)
  for k in 0 ..< (2 * r):
    for i in static(0 ..< 16):
      b[bOffset + k * 16 + (i * 5 mod 16)] = x[k * 16 + i]

template smix2(b: var seq[uint32], bOffset, r, n, nloop: int, mode: YescryptMode,
               v: var seq[uint32], vOffset: int, xy: var seq[uint32],
               ctx: var PwxCtx, haveCtx: bool): void =
  let s: int = 32 * r
  var x: seq[uint32] = newSeq[uint32](s)
  var y: seq[uint32] = newSeq[uint32](s)
  for k in 0 ..< (2 * r):
    for i in static(0..<16):
      x[k * 16 + i] = b[bOffset + k * 16 + (i * 5 mod 16)]
  for _ in 0 ..< nloop:
    let j: int = int(integerify(x, r) and uint64(n-1))

    for k in 0 ..< s:
      x[k] = x[k] xor v[vOffset + j * s + k]

    if mode == yescryptRw:
      for k in 0 ..< s:
        v[vOffset + j * s + k] = x[k]

    if haveCtx:
      blockmixPwx(ctx, x, r)
    else:
      blockmixSalsa8(x, y, r)

  for k in 0 ..< (2 * r):
    for i in static(0 ..< 16):
      b[bOffset + k * 16 + (i * 5 mod 16)] = x[k * 16 + i]

template smix(input: var seq[uint32]; r, n, p, t: int; mode: YescryptMode, password: var seq[uint8]): void =
  let s: int = 32 * r
  var v: seq[uint32] = newSeq[uint32](s * n)
  var xy: seq[uint32] = newSeq[uint32](2 * s)
  var nchunk: int = n div p
  var nloopAll: int = nchunk

  if mode == yescryptRw:
    if t <= 1:
      if t != 0: nloopAll *= 2
      nloopAll = (nloopAll + 2) div 3
    else: nloopAll *= t - 1
  elif t != 0:
    if t == 1: nloopAll += (nloopAll+1) div 2
    nloopAll*=t

  var nloopRw: int = if mode == yescryptRw: nloopAll div p else: 0
  nchunk = nchunk and not 1
  nloopAll = (nloopAll+1) and not 1
  nloopRw = (nloopRw+1) and not 1
  var contexts: seq[PwxCtx] = newSeq[PwxCtx](p)
  var vchunk = 0

  for lane in 0 ..< p:
    let np: int = if lane < p - 1: nchunk else: n - vchunk
    let boff: int = lane * s

    if mode == yescryptRw:
      var si: seq[uint32] = newSeq[uint32](SWords)
      var dummy: PwxCtx
      smix1(input, boff, 1, SWords div 32, yescryptClassic, si, 0, xy, dummy, false)
      contexts[lane].s2 = si[0..<1024]
      contexts[lane].s1 = si[1024..<2048]
      contexts[lane].s0 = si[2048..<3072]

      if lane == 0:
        let keyWords = input[(boff+s-16)..<(boff+s)]
        password = @(sha256HMAC(wordsToBytes(keyWords), password.toOpenArray(0, 31)))

    smix1(input, boff, r, np, mode, v, vchunk*s, xy, contexts[lane], mode == yescryptRw)
    smix2(input, boff, r, prevPowerOfTwo(np), nloopRw, mode, v, vchunk * s, xy, contexts[lane], mode == yescryptRw)
    vchunk += nchunk

  for lane in 0 ..< p:
    let secondMode = if mode == yescryptWorm: yescryptWorm else: yescryptClassic
    smix2(input, lane * s, r, n, nloopAll - nloopRw, secondMode, v, 0, xy, contexts[lane], mode == yescryptRw)

template yescryptBody(password, salt: openArray[uint8], params: YescryptCtx, keyLen: int; prehash: bool): seq[uint8] =
  let mode = params.mode
  var passwd = @password
  let domain: string = if prehash: "yescrypt-prehash" else: "yescrypt"

  if mode != yescryptClassic:
    passwd = @(sha256HMAC(domain.toOpenArrayByte(0, domain.high), passwd))

  var s: seq[uint8] = pbkdf2SHA256(passwd, salt, 1, 128 * params.r * params.p)
  var b = bytesToWords(s)

  if mode != yescryptClassic:
    passwd = wordsToBytes(b.toOpenArray(0, 7))

  if mode == yescryptRw:
    smix(b, params.r, params.n, params.p, params.t, mode, passwd)
  else:
    for lane in 0 ..< params.p:
      var one = b[lane * 32 * params.r..<((lane + 1) * 32 * params.r)]
      var ignored: seq[uint8]
      smix(one, params.r, params.n, 1, params.t, mode, ignored)
      for i, w in one: b[lane * 32 * params.r + i] = w
  let mixed = wordsToBytes(b)
  var derived = pbkdf2SHA256(passwd, mixed, 1, keyLen)
  if mode != yescryptClassic and not prehash:
    let dk = if keyLen < 32: pbkdf2SHA256(passwd, mixed, 1, 32) else: derived
    let str: seq[uint8] = charToBin("Client Key".toOpenArray(0, 9))
    let client = sha256HMAC(dk.toOpenArray(0, 31), str)
    let stored = sha256One(client)
    for i in 0 ..< min(keyLen, 32):
      derived[i] = stored[i]

  derived

template yescrypt*(password, salt: openArray[uint8], params: YescryptCtx, keyLen: int): seq[uint8] =
  if keyLen < 1 or params.n <= 1 or (params.n and (params.n-1)) != 0 or
     params.r < 1 or params.p < 1 or params.t < 0 or
     (params.mode == yescryptRw and params.n div params.p <= 1):
    raise newException(KdfError, "invalid yescrypt parameters")
  if params.r > high(int) div (128 * params.p) or
     params.n > high(int) div (128 * params.r):
    raise newException(KdfError, "yescrypt parameters overflow address space")
  var passwd: seq[uint8] = @password
  if params.mode == yescryptRw and params.n div params.p >= 0x100 and
     (params.n div params.p)*params.r >= 0x20000:
    var reduced: YescryptCtx = params
    reduced.n = reduced.n shr 6
    reduced.t = 0
    passwd = yescryptBody(passwd, salt, reduced, 32, true)
  yescryptBody(passwd, salt, params, keyLen, false)

proc yescrypt*(password, salt: openArray[uint8], n, r, p, keyLen: int, mode: YescryptMode = yescryptRw, t: int = 0): seq[uint8] =
  yescrypt(password, salt, yescryptInit(mode, n, r, p, t), keyLen)
