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


# SHA-2 256 series : SHA-2-224, SHA-2-256 : for 32 bits
# SHA-2 512 series : SHA-2-384, SHA-2-512, SHA-2-512/224, SHA-2-512/256 : for 64 bits

# declaring constant
const
  # K for 256 series
  K256: array[64, uint32] = [
    0x428a2f98'u32, 0x71374491'u32, 0xb5c0fbcf'u32, 0xe9b5dba5'u32, 0x3956c25b'u32, 0x59f111f1'u32, 0x923f82a4'u32, 0xab1c5ed5'u32,
    0xd807aa98'u32, 0x12835b01'u32, 0x243185be'u32, 0x550c7dc3'u32, 0x72be5d74'u32, 0x80deb1fe'u32, 0x9bdc06a7'u32, 0xc19bf174'u32,
    0xe49b69c1'u32, 0xefbe4786'u32, 0x0fc19dc6'u32, 0x240ca1cc'u32, 0x2de92c6f'u32, 0x4a7484aa'u32, 0x5cb0a9dc'u32, 0x76f988da'u32,
    0x983e5152'u32, 0xa831c66d'u32, 0xb00327c8'u32, 0xbf597fc7'u32, 0xc6e00bf3'u32, 0xd5a79147'u32, 0x06ca6351'u32, 0x14292967'u32,
    0x27b70a85'u32, 0x2e1b2138'u32, 0x4d2c6dfc'u32, 0x53380d13'u32, 0x650a7354'u32, 0x766a0abb'u32, 0x81c2c92e'u32, 0x92722c85'u32,
    0xa2bfe8a1'u32, 0xa81a664b'u32, 0xc24b8b70'u32, 0xc76c51a3'u32, 0xd192e819'u32, 0xd6990624'u32, 0xf40e3585'u32, 0x106aa070'u32,
    0x19a4c116'u32, 0x1e376c08'u32, 0x2748774c'u32, 0x34b0bcb5'u32, 0x391c0cb3'u32, 0x4ed8aa4a'u32, 0x5b9cca4f'u32, 0x682e6ff3'u32,
    0x748f82ee'u32, 0x78a5636f'u32, 0x84c87814'u32, 0x8cc70208'u32, 0x90befffa'u32, 0xa4506ceb'u32, 0xbef9a3f7'u32, 0xc67178f2'u32
  ]

  # K for 512 series
  K512: array[80, uint64] = [
  0x428a2f98d728ae22'u64, 0x7137449123ef65cd'u64, 0xb5c0fbcfec4d3b2f'u64, 0xe9b5dba58189dbbc'u64, 0x3956c25bf348b538'u64,
  0x59f111f1b605d019'u64, 0x923f82a4af194f9b'u64, 0xab1c5ed5da6d8118'u64, 0xd807aa98a3030242'u64, 0x12835b0145706fbe'u64,
  0x243185be4ee4b28c'u64, 0x550c7dc3d5ffb4e2'u64, 0x72be5d74f27b896f'u64, 0x80deb1fe3b1696b1'u64, 0x9bdc06a725c71235'u64,
  0xc19bf174cf692694'u64, 0xe49b69c19ef14ad2'u64, 0xefbe4786384f25e3'u64, 0x0fc19dc68b8cd5b5'u64, 0x240ca1cc77ac9c65'u64,
  0x2de92c6f592b0275'u64, 0x4a7484aa6ea6e483'u64, 0x5cb0a9dcbd41fbd4'u64, 0x76f988da831153b5'u64, 0x983e5152ee66dfab'u64,
  0xa831c66d2db43210'u64, 0xb00327c898fb213f'u64, 0xbf597fc7beef0ee4'u64, 0xc6e00bf33da88fc2'u64, 0xd5a79147930aa725'u64,
  0x06ca6351e003826f'u64, 0x142929670a0e6e70'u64, 0x27b70a8546d22ffc'u64, 0x2e1b21385c26c926'u64, 0x4d2c6dfc5ac42aed'u64,
  0x53380d139d95b3df'u64, 0x650a73548baf63de'u64, 0x766a0abb3c77b2a8'u64, 0x81c2c92e47edaee6'u64, 0x92722c851482353b'u64,
  0xa2bfe8a14cf10364'u64, 0xa81a664bbc423001'u64, 0xc24b8b70d0f89791'u64, 0xc76c51a30654be30'u64, 0xd192e819d6ef5218'u64,
  0xd69906245565a910'u64, 0xf40e35855771202a'u64, 0x106aa07032bbd1b8'u64, 0x19a4c116b8d2d0c8'u64, 0x1e376c085141ab53'u64,
  0x2748774cdf8eeb99'u64, 0x34b0bcb5e19b48a8'u64, 0x391c0cb3c5c95a63'u64, 0x4ed8aa4ae3418acb'u64, 0x5b9cca4f7763e373'u64,
  0x682e6ff3d6b2b8a3'u64, 0x748f82ee5defb2fc'u64, 0x78a5636f43172f60'u64, 0x84c87814a1f0ab72'u64, 0x8cc702081a6439ec'u64,
  0x90befffa23631e28'u64, 0xa4506cebde82bde9'u64, 0xbef9a3f7b2c67915'u64, 0xc67178f2e372532b'u64, 0xca273eceea26619c'u64,
  0xd186b8c721c0c207'u64, 0xeada7dd6cde0eb1e'u64, 0xf57d4f7fee6ed178'u64, 0x06f067aa72176fba'u64, 0x0a637dc5a2c898a6'u64,
  0x113f9804bef90dae'u64, 0x1b710b35131c471b'u64, 0x28db77f523047d84'u64, 0x32caab7b40c72493'u64, 0x3c9ebe0a15c9bebc'u64,
  0x431d67c49c100d4c'u64, 0x4cc5d4becb3e42b6'u64, 0x597f299cfc657e2a'u64, 0x5fcb6fab3ad6faec'u64, 0x6c44198c4a475817'u64
  ]

# sizeOpt : optimise binary size
# activate when binary have to small
# use proc, use runtime for loop
when defined(sizeOpt):
 # sha2 transform for 256 series
 # state : ctx.state
 # input : input message
  proc sha2Transform256(state: var array[8, uint32], input: slicearray[64, uint8]): void =
    # declare w
    var w: array[64, uint32]

    # decode input to w
    decodeBE(input, w.toSliceArray(0, 15))

    # extend w
    for i in 16 ..< 64:
      let s0 = rightRotate(w[i - 15], 7) xor rightRotate(w[i - 15], 18) xor (w[i - 15] shr 3)
      let s1 = rightRotate(w[i - 2], 17) xor rightRotate(w[i - 2], 19) xor (w[i - 2] shr 10)
      w[i] = w[i - 16] + s0 + w[i - 7] + s1

    # declare and initialize temporary variables
    var a: uint32 = state[0]
    var b: uint32 = state[1]
    var c: uint32 = state[2]
    var d: uint32 = state[3]
    var e: uint32 = state[4]
    var f: uint32 = state[5]
    var g: uint32 = state[6]
    var h: uint32 = state[7]
    
    # round loop : 64 rounds
    for i in 0 ..< 64:
      let S1 = rightRotate(e, 6) xor rightRotate(e, 11) xor rightRotate(e, 25)
      let ch = (e and f) xor ((not e) and g)
      let temp1 = h + S1 + ch + K256[i] + w[i]
      let S0 = rightRotate(a, 2) xor rightRotate(a, 13) xor rightRotate(a, 22)
      let maj = (a and b) xor (a and c) xor (b and c)
      let temp2 = S0 + maj

      h = g
      g = f
      f = e
      e = d + temp1
      d = c
      c = b
      b = a
      a = temp1 + temp2

    # add and assign temporary variables to state
    state[0] += a
    state[1] += b
    state[2] += c
    state[3] += d
    state[4] += e
    state[5] += f
    state[6] += g
    state[7] += h

  # sha2 transform for 512 series
  # state : ctx.state
  # input : input message
  proc sha2Transform512(state: var array[8, uint64], input: slicearray[128, uint8]): void =
    # declare w
    var w: array[80, uint64]

    # decode input to w
    decodeBE(input, w.toSliceArray(0, 15))

    # extend w
    for i in 16 ..< 80:
      let s0 = rightRotate(w[i - 15], 1) xor rightRotate(w[i - 15], 8) xor (w[i - 15] shr 7)
      let s1 = rightRotate(w[i - 2], 19) xor rightRotate(w[i - 2], 61) xor (w[i - 2] shr 6)
      w[i] = w[i - 16] + s0 + w[i - 7] + s1

    # declare and initialize temporary variables
    var a: uint64 = state[0]
    var b: uint64 = state[1]
    var c: uint64 = state[2]
    var d: uint64 = state[3]
    var e: uint64 = state[4]
    var f: uint64 = state[5]
    var g: uint64 = state[6]
    var h: uint64 = state[7]

    # round loop : 80 rounds
    for i in 0 ..< 80:
      let S1 = rightRotate(e,14) xor rightRotate(e,18) xor rightRotate(e,41)
      let ch = (e and f) xor ((not e) and g)
      let temp1 = h + S1 + ch + K512[i] + w[i]
      let S0 = rightRotate(a,28) xor rightRotate(a,34) xor rightRotate(a,39)
      let maj = (a and b) xor (a and c) xor (b and c)
      let temp2 = S0 + maj

      h = g
      g = f
      f = e
      e = d + temp1
      d = c
      c = b
      b = a
      a = temp1 + temp2

    # add and assign temporary variables to state
    state[0] += a
    state[1] += b
    state[2] += c
    state[3] += d
    state[4] += e
    state[5] += f
    state[6] += g
    state[7] += h
else:
  # chunk extend template for 256 series
  template extend256(chunk: var array[16, uint32], index: static int): uint32 =
    let i: int = index and 15
    let s0: uint32 = rotateRightBits(chunk[(i + 1) and 15], 7) xor rotateRightBits(chunk[(i + 1) and 15], 18) xor (chunk[(i + 1) and 15] shr 3)
    let s1: uint32 = rotateRightBits(chunk[(i + 14) and 15], 17) xor rotateRightBits(chunk[(i + 14) and 15], 19) xor (chunk[(i + 14) and 15] shr 10)
    chunk[i] = chunk[i] + s0 + chunk[(i + 9) and 15] + s1
    chunk[i]

  # pre-round template for 256 seriess
  template preround256(a, b, c, d, e, f, g, h: var uint32, w: var array[16, uint32], index: static int): void =
    let s1: uint32 = rotateRightBits(e, 6) xor rotateRightBits(e, 11) xor rotateRightBits(e, 25)
    let ch: uint32 = (e and f) xor ((not e) and g)
    let temp1: uint32 = h + s1 + ch + K256[index] + w[index]

    let s0: uint32 = rotateRightBits(a, 2) xor rotateRightBits(a, 13) xor rotateRightBits(a, 22)
    let maj: uint32 = (a and b) xor (a and c) xor (b and c)
    let temp2: uint32 = s0 + maj

    d += temp1
    h = temp1 + temp2

  # round template for 256 series
  template round256(a, b, c, d, e, f, g, h: var uint32, w: var array[16, uint32], index: static int): void =
    let s1: uint32 = rotateRightBits(e, 6) xor rotateRightBits(e, 11) xor rotateRightBits(e, 25)
    let ch: uint32 = (e and f) xor ((not e) and g)
    let temp1: uint32 = h + s1 + ch + K256[index] + extend256(w, index)

    let s0: uint32 = rotateRightBits(a, 2) xor rotateRightBits(a, 13) xor rotateRightBits(a, 22)
    let maj: uint32 = (a and b) xor (a and c) xor (b and c)
    let temp2: uint32 = s0 + maj

    d += temp1
    h = temp1 + temp2

  # sha2 transform template for 256 series
  template sha2Transform256(state: var array[8, uint32], input: slicearray[64, uint8]): void =
    # declare chunk
    var chunk: array[16, uint32]

    # decode input to chunk
    decodeBE(input, chunk.toSliceArray(0, 15))

    # declare and initialize temporary variables
    var a: uint32 = state[0]
    var b: uint32 = state[1]
    var c: uint32 = state[2]
    var d: uint32 = state[3]
    var e: uint32 = state[4]
    var f: uint32 = state[5]
    var g: uint32 = state[6]
    var h: uint32 = state[7]

    # call pre-round template(not include extend template) : 0 ~ 15
    preround256(a, b, c, d, e, f, g, h, chunk, 0)
    preround256(h, a, b, c, d, e, f, g, chunk, 1)
    preround256(g, h, a, b, c, d, e, f, chunk, 2)
    preround256(f, g, h, a, b, c, d, e, chunk, 3)
    preround256(e, f, g, h, a, b, c, d, chunk, 4)
    preround256(d, e, f, g, h, a, b, c, chunk, 5)
    preround256(c, d, e, f, g, h, a, b, chunk, 6)
    preround256(b, c, d, e, f, g, h, a, chunk, 7)
    preround256(a, b, c, d, e, f, g, h, chunk, 8)
    preround256(h, a, b, c, d, e, f, g, chunk, 9)
    preround256(g, h, a, b, c, d, e, f, chunk, 10)
    preround256(f, g, h, a, b, c, d, e, chunk, 11)
    preround256(e, f, g, h, a, b, c, d, chunk, 12)
    preround256(d, e, f, g, h, a, b, c, chunk, 13)
    preround256(c, d, e, f, g, h, a, b, chunk, 14)
    preround256(b, c, d, e, f, g, h, a, chunk, 15)

    # call round template(include extend template) : 16 ~ 63
    round256(a, b, c, d, e, f, g, h, chunk, 16)
    round256(h, a, b, c, d, e, f, g, chunk, 17)
    round256(g, h, a, b, c, d, e, f, chunk, 18)
    round256(f, g, h, a, b, c, d, e, chunk, 19)
    round256(e, f, g, h, a, b, c, d, chunk, 20)
    round256(d, e, f, g, h, a, b, c, chunk, 21)
    round256(c, d, e, f, g, h, a, b, chunk, 22)
    round256(b, c, d, e, f, g, h, a, chunk, 23)
    round256(a, b, c, d, e, f, g, h, chunk, 24)
    round256(h, a, b, c, d, e, f, g, chunk, 25)
    round256(g, h, a, b, c, d, e, f, chunk, 26)
    round256(f, g, h, a, b, c, d, e, chunk, 27)
    round256(e, f, g, h, a, b, c, d, chunk, 28)
    round256(d, e, f, g, h, a, b, c, chunk, 29)
    round256(c, d, e, f, g, h, a, b, chunk, 30)
    round256(b, c, d, e, f, g, h, a, chunk, 31)
    round256(a, b, c, d, e, f, g, h, chunk, 32)
    round256(h, a, b, c, d, e, f, g, chunk, 33)
    round256(g, h, a, b, c, d, e, f, chunk, 34)
    round256(f, g, h, a, b, c, d, e, chunk, 35)
    round256(e, f, g, h, a, b, c, d, chunk, 36)
    round256(d, e, f, g, h, a, b, c, chunk, 37)
    round256(c, d, e, f, g, h, a, b, chunk, 38)
    round256(b, c, d, e, f, g, h, a, chunk, 39)
    round256(a, b, c, d, e, f, g, h, chunk, 40)
    round256(h, a, b, c, d, e, f, g, chunk, 41)
    round256(g, h, a, b, c, d, e, f, chunk, 42)
    round256(f, g, h, a, b, c, d, e, chunk, 43)
    round256(e, f, g, h, a, b, c, d, chunk, 44)
    round256(d, e, f, g, h, a, b, c, chunk, 45)
    round256(c, d, e, f, g, h, a, b, chunk, 46)
    round256(b, c, d, e, f, g, h, a, chunk, 47)
    round256(a, b, c, d, e, f, g, h, chunk, 48)
    round256(h, a, b, c, d, e, f, g, chunk, 49)
    round256(g, h, a, b, c, d, e, f, chunk, 50)
    round256(f, g, h, a, b, c, d, e, chunk, 51) 
    round256(e, f, g, h, a, b, c, d, chunk, 52)
    round256(d, e, f, g, h, a, b, c, chunk, 53)
    round256(c, d, e, f, g, h, a, b, chunk, 54)
    round256(b, c, d, e, f, g, h, a, chunk, 55)
    round256(a, b, c, d, e, f, g, h, chunk, 56)
    round256(h, a, b, c, d, e, f, g, chunk, 57)
    round256(g, h, a, b, c, d, e, f, chunk, 58)
    round256(f, g, h, a, b, c, d, e, chunk, 59)
    round256(e, f, g, h, a, b, c, d, chunk, 60)
    round256(d, e, f, g, h, a, b, c, chunk, 61)
    round256(c, d, e, f, g, h, a, b, chunk, 62)
    round256(b, c, d, e, f, g, h, a, chunk, 63)

    # add and assign temporary variables to state
    state[0] += a
    state[1] += b
    state[2] += c
    state[3] += d
    state[4] += e
    state[5] += f
    state[6] += g
    state[7] += h

  # chunk extend template for 512 series
  template extend512(chunk: var array[16, uint64], index: static int): uint64 =
    let i: int = index and 15
    let s0: uint64 = rotateRightBits(chunk[(i + 1) and 15], 1) xor rotateRightBits(chunk[(i + 1) and 15], 8) xor (chunk[(i + 1) and 15] shr 7)
    let s1: uint64 = rotateRightBits(chunk[(i + 14) and 15], 19) xor rotateRightBits(chunk[(i + 14) and 15], 61) xor (chunk[(i + 14) and 15] shr 6)

    chunk[i] = chunk[i] + s0 + chunk[(i + 9) and 15] + s1
    chunk[i]

  # pre-round template for 512 series
  template preround512(a, b, c, d, e, f, g, h: var uint64, w: var array[16, uint64], index: static int): void =
    let s1: uint64 = rotateRightBits(e, 14) xor rotateRightBits(e, 18) xor rotateRightBits(e, 41)
    let ch: uint64 = (e and f) xor ((not e) and g)
    let temp1: uint64 = h + s1 + ch + K512[index] + w[index]

    let s0: uint64 = rotateRightBits(a, 28) xor rotateRightBits(a, 34) xor rotateRightBits(a, 39)
    let maj: uint64 = (a and b) xor (a and c) xor (b and c)
    let temp2: uint64 = s0 + maj

    d += temp1
    h = temp1 + temp2

  # round template for 512 series
  template round512(a, b, c, d, e, f, g, h: var uint64, w: var array[16, uint64], index: static int): void =
    let s1: uint64 = rotateRightBits(e, 14) xor rotateRightBits(e, 18) xor rotateRightBits(e, 41)
    let ch: uint64 = (e and f) xor ((not e) and g)
    let temp1: uint64 = h + s1 + ch + K512[index] + extend512(w, index)

    let s0: uint64 = rotateRightBits(a, 28) xor rotateRightBits(a, 34) xor rotateRightBits(a, 39)
    let maj: uint64 = (a and b) xor (a and c) xor (b and c)
    let temp2: uint64 = s0 + maj

    d += temp1
    h = temp1 + temp2

  # sha2 transform template for 512 series
  template sha2Transform512(state: var array[8, uint64], input: slicearray[128, uint8]): void =
    # declare chunk
    var chunk: array[16, uint64]

    # decode input to chunk
    decodeBE(input, chunk.toSliceArray(0, 15))

    # declare and initialize temporary variables
    var a: uint64 = state[0]
    var b: uint64 = state[1]
    var c: uint64 = state[2]
    var d: uint64 = state[3]
    var e: uint64 = state[4]
    var f: uint64 = state[5]
    var g: uint64 = state[6]
    var h: uint64 = state[7]

    # call pre-round template(not include extend template) : 0 ~ 15
    preround512(a, b, c, d, e, f, g, h, chunk, 0)
    preround512(h, a, b, c, d, e, f, g, chunk, 1)
    preround512(g, h, a, b, c, d, e, f, chunk, 2)
    preround512(f, g, h, a, b, c, d, e, chunk, 3)
    preround512(e, f, g, h, a, b, c, d, chunk, 4)
    preround512(d, e, f, g, h, a, b, c, chunk, 5)
    preround512(c, d, e, f, g, h, a, b, chunk, 6)
    preround512(b, c, d, e, f, g, h, a, chunk, 7)
    preround512(a, b, c, d, e, f, g, h, chunk, 8)
    preround512(h, a, b, c, d, e, f, g, chunk, 9)
    preround512(g, h, a, b, c, d, e, f, chunk, 10)
    preround512(f, g, h, a, b, c, d, e, chunk, 11)
    preround512(e, f, g, h, a, b, c, d, chunk, 12)
    preround512(d, e, f, g, h, a, b, c, chunk, 13)
    preround512(c, d, e, f, g, h, a, b, chunk, 14)
    preround512(b, c, d, e, f, g, h, a, chunk, 15)

    # call round template(include extend template) : 16 ~ 79
    round512(a, b, c, d, e, f, g, h, chunk, 16)
    round512(h, a, b, c, d, e, f, g, chunk, 17)
    round512(g, h, a, b, c, d, e, f, chunk, 18)
    round512(f, g, h, a, b, c, d, e, chunk, 19)
    round512(e, f, g, h, a, b, c, d, chunk, 20)
    round512(d, e, f, g, h, a, b, c, chunk, 21)
    round512(c, d, e, f, g, h, a, b, chunk, 22)
    round512(b, c, d, e, f, g, h, a, chunk, 23)
    round512(a, b, c, d, e, f, g, h, chunk, 24)
    round512(h, a, b, c, d, e, f, g, chunk, 25)
    round512(g, h, a, b, c, d, e, f, chunk, 26)
    round512(f, g, h, a, b, c, d, e, chunk, 27)
    round512(e, f, g, h, a, b, c, d, chunk, 28)
    round512(d, e, f, g, h, a, b, c, chunk, 29)
    round512(c, d, e, f, g, h, a, b, chunk, 30)
    round512(b, c, d, e, f, g, h, a, chunk, 31)
    round512(a, b, c, d, e, f, g, h, chunk, 32)
    round512(h, a, b, c, d, e, f, g, chunk, 33)
    round512(g, h, a, b, c, d, e, f, chunk, 34)
    round512(f, g, h, a, b, c, d, e, chunk, 35)
    round512(e, f, g, h, a, b, c, d, chunk, 36)
    round512(d, e, f, g, h, a, b, c, chunk, 37)
    round512(c, d, e, f, g, h, a, b, chunk, 38)
    round512(b, c, d, e, f, g, h, a, chunk, 39)
    round512(a, b, c, d, e, f, g, h, chunk, 40)
    round512(h, a, b, c, d, e, f, g, chunk, 41)
    round512(g, h, a, b, c, d, e, f, chunk, 42)
    round512(f, g, h, a, b, c, d, e, chunk, 43)
    round512(e, f, g, h, a, b, c, d, chunk, 44)
    round512(d, e, f, g, h, a, b, c, chunk, 45)
    round512(c, d, e, f, g, h, a, b, chunk, 46)
    round512(b, c, d, e, f, g, h, a, chunk, 47)
    round512(a, b, c, d, e, f, g, h, chunk, 48)
    round512(h, a, b, c, d, e, f, g, chunk, 49)
    round512(g, h, a, b, c, d, e, f, chunk, 50)
    round512(f, g, h, a, b, c, d, e, chunk, 51)
    round512(e, f, g, h, a, b, c, d, chunk, 52)
    round512(d, e, f, g, h, a, b, c, chunk, 53)
    round512(c, d, e, f, g, h, a, b, chunk, 54)
    round512(b, c, d, e, f, g, h, a, chunk, 55)
    round512(a, b, c, d, e, f, g, h, chunk, 56)
    round512(h, a, b, c, d, e, f, g, chunk, 57)
    round512(g, h, a, b, c, d, e, f, chunk, 58)
    round512(f, g, h, a, b, c, d, e, chunk, 59)
    round512(e, f, g, h, a, b, c, d, chunk, 60)
    round512(d, e, f, g, h, a, b, c, chunk, 61)
    round512(c, d, e, f, g, h, a, b, chunk, 62)
    round512(b, c, d, e, f, g, h, a, chunk, 63)
    round512(a, b, c, d, e, f, g, h, chunk, 64)
    round512(h, a, b, c, d, e, f, g, chunk, 65)
    round512(g, h, a, b, c, d, e, f, chunk, 66)
    round512(f, g, h, a, b, c, d, e, chunk, 67)
    round512(e, f, g, h, a, b, c, d, chunk, 68)
    round512(d, e, f, g, h, a, b, c, chunk, 69)
    round512(c, d, e, f, g, h, a, b, chunk, 70)
    round512(b, c, d, e, f, g, h, a, chunk, 71)
    round512(a, b, c, d, e, f, g, h, chunk, 72)
    round512(h, a, b, c, d, e, f, g, chunk, 73)
    round512(g, h, a, b, c, d, e, f, chunk, 74)
    round512(f, g, h, a, b, c, d, e, chunk, 75)
    round512(e, f, g, h, a, b, c, d, chunk, 76)
    round512(d, e, f, g, h, a, b, c, chunk, 77)
    round512(c, d, e, f, g, h, a, b, chunk, 78)
    round512(b, c, d, e, f, g, h, a, chunk, 79)

    # add and assign temporary variables to state
    state[0] += a
    state[1] += b
    state[2] += c
    state[3] += d
    state[4] += e
    state[5] += f
    state[6] += g
    state[7] += h

# chunking template of 256 series : only used in one shot version
template chunking256(state: var array[8, uint32], input: openArray[uint8]): void {.autoSizeOpt.} =
  # calculate chunk count
  let chunkCount = input.len div 64

  # divide chunk and call transform
  for i in 0 ..< chunkCount:
    sha2Transform256(state, input.toSliceArray(i * 64, i * 64 + 63, 64))

# chunking template of 512 series : only used in one shot version
template chunking512(state: var array[8, uint64], input: openArray[uint8]): void {.autoSizeOpt.} =
  # calculate chunk count
  let chunkCount = input.len div 128

  # divide chunk and call transform
  for i in 0 ..< chunkCount:
    sha2Transform512(state, input.toSliceArray(i * 128, i * 128 + 127, 128))

# padding template for 256 series : only used in one shot version
template padding256(input: openArray[uint8], inputLen: int): seq[uint8] {.autoSizeOpt.} =
  # calculate total length : memory allocating optimise
  let totalLen: int = ((inputLen + 9 + 63) div 64) * 64

  # set buffer
  var buffer: seq[uint8] = newSeq[uint8](totalLen)
  # copy input to buffer
  copyMem(addr buffer[0], addr input[0], inputLen)
  var index: int = inputLen
  
  # add padding : 0x80
  buffer[index] = 0x80'u8
  index += 1

  # zerofill
  let padLen: int = totalLen - index - 8
  zeroMem(addr buffer[index], padLen)
  index += padLen
  
  # add length
  let bitLen: uint64 = uint64(inputLen) shl 3
  toBytesBE(bitLen, buffer.toSliceArray(index, index + 7, 8))

  buffer

# padding template for 512 series : only used in one shot version
template padding512(input: openArray[uint8], inputLen: int): seq[uint8] {.autoSizeOpt.} =
  # calculate total length : memory allocating optimise
  let totalLen: int = ((inputLen + 17 + 127) div 128) * 128

  # set buffer
  var buffer: seq[uint8] = newSeq[uint8](totalLen)
  # copy input to buffer
  copyMem(addr buffer[0], addr input[0], inputLen)
  var index: int = inputLen
  
  # add padding : 0x80
  buffer[index] = 0x80'u8
  index += 1

  # zerofill
  let padLen: int = totalLen - index - 16
  zeroMem(addr buffer[index], padLen)
  index += padLen
  
  # add length
  let bitLen: array[2, uint64] = [uint64(inputLen) shr 61, uint64(inputLen) shl 3]
  encodeBE(bitLen.toSliceArray(0, 1), buffer.toSliceArray(index, index + 15, 16))

  buffer

# SHA-2-224 oneshot core
template sha2_224OneC(input: openArray[uint8]): array[28, uint8] {.autoSizeOpt.} =
  # declare output
  var output: array[28, uint8]
  let inputLen: int = input.len

  # declare state
  var state: array[8, uint32] = [
  0xc1059ed8'u32, 0x367cd507'u32, 0x3070dd17'u32, 0xf70e5939'u32, 0xffc00b31'u32, 0x68581511'u32, 0x64f98fa7'u32, 0xbefa4fa4'u32
  ]

  # call padding256
  var buffer: seq[uint8] = padding256(input, inputLen)

  # call chunking256
  chunking256(state, buffer)

  # encode state to output by big endian(slicearray version)
  encodeBE(state.toSliceArray(0, 6), output.toSliceArray(0, 27))

  output

# SHA-2-256 oneshot core
template sha2_256OneC(input: openArray[uint8]): array[32, uint8] {.autoSizeOpt.} =
  # declare output
  var output: array[32, uint8]
  let inputLen: int = input.len

  # declare state
  var state: array[8, uint32] = [
  0x6a09e667'u32, 0xbb67ae85'u32, 0x3c6ef372'u32, 0xa54ff53a'u32, 0x510e527f'u32, 0x9b05688c'u32, 0x1f83d9ab'u32, 0x5be0cd19'u32
  ]

  # call padding256
  var buffer: seq[uint8] = padding256(input, inputLen)

  # call chunking256
  chunking256(state, buffer)

  # encode state to output by big endian(array version)
  encodeBE(state, output)

  output

# SHA-2-384 oneshot core
template sha2_384OneC(input: openArray[uint8]): array[48, uint8] {.autoSizeOpt.} =
  # declare output
  var output: array[48, uint8]
  let inputLen: int = input.len

  #declare state
  var state: array[8, uint64] = [
  0xcbbb9d5dc1059ed8'u64, 0x629a292a367cd507'u64, 0x9159015a3070dd17'u64, 0x152fecd8f70e5939'u64,
  0x67332667ffc00b31'u64, 0x8eb44a8768581511'u64, 0xdb0c2e0d64f98fa7'u64, 0x47b5481dbefa4fa4'u64
  ]

  # call padding512
  var buffer: seq[uint8] = padding512(input, inputLen)

  # call chunking512
  chunking512(state, buffer)

  # encode state to output by big endian(slicearry version)
  encodeBE(state.toSliceArray(0, 5), output.toSliceArray(0, 47))

  output

# SHA-2-512 oneshot core
template sha2_512OneC(input: openArray[uint8]): array[64, uint8] {.autoSizeOpt.} =
  # declare output
  var output: array[64, uint8]
  let inputLen: int = input.len

  # declare state
  var state: array[8, uint64] = [
  0x6a09e667f3bcc908'u64, 0xbb67ae8584caa73b'u64, 0x3c6ef372fe94f82b'u64, 0xa54ff53a5f1d36f1'u64,
  0x510e527fade682d1'u64, 0x9b05688c2b3e6c1f'u64, 0x1f83d9abfb41bd6b'u64, 0x5be0cd19137e2179'u64
  ]

  # call padding512
  var buffer: seq[uint8] = padding512(input, inputLen)

  # call chunking512
  chunking512(state, buffer)

  # encdoe state to output by big endian(array version)
  encodeBE(state, output)

  output

# SHA-2-512/224 oneshot core
template sha2_512_224OneC(input: openArray[uint8]): array[28, uint8] {.autoSizeOpt.} =
  # declare output
  var output: array[28, uint8]
  # copy input to buffer
  let inputLen: int = input.len

  # declare state
  var state: array[8, uint64] = [
  0x8c3d37c819544da2'u64, 0x73e1996689dcd4d6'u64, 0x1dfab7ae32ff9c82'u64, 0x679dd514582f9fcf'u64,
  0x0f6d2b697bd44da8'u64, 0x77e36f7304C48942'u64, 0x3f9d85a86a1d36C8'u64, 0x1112e6ad91d692a1'u64
  ]

  # call padding512
  var buffer: seq[uint8] = padding512(input, inputLen)

  # call chunking512
  chunking512(state, buffer)

  # encode state to temp(openArray)
  var temp: array[32, uint8]
  # discard result because state's index is verified in compile time
  encodeBE(state.toSliceArray(0, 3), temp.toSliceArray(0, 31))
  # copy temp to output
  copyMem(addr output[0], addr temp[0], 28)

  output

# SHA-2-512/224 oneshot core
template sha2_512_256OneC(input: openArray[uint8]): array[32, uint8] {.autoSizeOpt.} =
  # declare output
  var output: array[32, uint8]
  let inputLen: int = input.len

  # declare state
  var state: array[8, uint64] = [
  0x22312194fc2bf72c'u64, 0x9f555fa3c84c64c2'u64, 0x2393b86b6f53b151'u64, 0x963877195940eabd'u64,
  0x96283ee2a88effe3'u64, 0xbe5e1e2553863992'u64, 0x2b0199fc2c85b8aa'u64, 0x0eb72ddC81c52ca2'u64
  ]

  # call padding512
  var buffer: seq[uint8] = padding512(input, inputLen)

  # call chunking512
  chunking512(state, buffer)

  # encode state to output(openArray)
  # discard result because state's index is verified in compile time
  encodeBE(state.toSliceArray(0, 3), output.toSliceArray(0, 31))

  output

const
  # declare hash size constant
  SHA2_224_HASH_SIZE*: int = 224 div 8
  SHA2_256_HASH_SIZE*: int = 256 div 8
  SHA2_384_HASH_SIZE*: int = 384 div 8
  SHA2_512_HASH_SIZE*: int = 512 div 8

  # # declare block size constant
  SHA2_256_BLOCK_SIZE*: int = 512 div 8
  SHA2_512_BLOCK_SIZE*: int = 1024 div 8
  SHA2_224_BLOCK_SIZE*: int = SHA2_256_BLOCK_SIZE
  SHA2_384_BLOCK_SIZE*: int = SHA2_512_BLOCK_SIZE
  SHA2_512_224_BLOCK_SIZE*: int = SHA2_512_BLOCK_SIZE
  SHA2_512_256_BLOCK_SIZE*: int = SHA2_512_BLOCK_SIZE

type
  SHA2Kind* = enum
    SHA2_224
    SHA2_256
    SHA2_384
    SHA2_512
    SHA2_512_224
    SHA2_512_256

# declare generic SHA-2 context for 64bits
type
  SHA2Ctx*[blockSize: static[int], hashSize: static[int], T; kind: static SHA2Kind] = object
    length*: array[2, T]
    index*: int
    buffer*: array[blockSize, uint8]
    state*: array[8, T]

type
  # declare SHA-2 context by generic context
  SHA2_224Ctx* = SHA2Ctx[SHA2_224_BLOCK_SIZE, SHA2_224_HASH_SIZE, uint32, SHA2_224]
  SHA2_256Ctx* = SHA2Ctx[SHA2_256_BLOCK_SIZE, SHA2_256_HASH_SIZE, uint32, SHA2_256]
  SHA2_384Ctx* = SHA2Ctx[SHA2_384_BLOCK_SIZE, SHA2_384_HASH_SIZE, uint64, SHA2_384]
  SHA2_512Ctx* = SHA2Ctx[SHA2_512_BLOCK_SIZE, SHA2_512_HASH_SIZE, uint64, SHA2_512]
  SHA2_512_224Ctx* = SHA2Ctx[SHA2_512_224_BLOCK_SIZE, SHA2_224_HASH_SIZE, uint64, SHA2_512_224]
  SHA2_512_256Ctx* = SHA2Ctx[SHA2_512_256_BLOCK_SIZE, SHA2_256_HASH_SIZE, uint64, SHA2_512_256]

template sha2InitC[B: static[int], H: static[int], T; K: static SHA2Kind](ctx: var SHA2Ctx[B, H, T, K]): void {.autoSizeOpt.} =
  zeroMem(addr ctx.buffer[0], B)

  when T is uint64:
    ctx.length[0] = 0x00'u64
    ctx.length[1] = 0x00'u64
  elif T is uint32:
    ctx.length[0] = 0x00'u32
    ctx.length[1] = 0x00'u32

  ctx.index = 0

  when K == SHA2_224:
    ctx.state[0] = 0xC1059ED8'u32
    ctx.state[1] = 0x367CD507'u32
    ctx.state[2] = 0x3070DD17'u32
    ctx.state[3] = 0xF70E5939'u32
    ctx.state[4] = 0xFFC00B31'u32
    ctx.state[5] = 0x68581511'u32
    ctx.state[6] = 0x64F98FA7'u32
    ctx.state[7] = 0xBEFA4FA4'u32
  elif K == SHA2_256:
    ctx.state[0] = 0x6A09E667'u32
    ctx.state[1] = 0xBB67AE85'u32
    ctx.state[2] = 0x3C6EF372'u32
    ctx.state[3] = 0xA54FF53A'u32
    ctx.state[4] = 0x510E527F'u32
    ctx.state[5] = 0x9B05688C'u32
    ctx.state[6] = 0x1F83D9AB'u32
    ctx.state[7] = 0x5BE0CD19'u32
  elif K == SHA2_384:
    ctx.state[0] = 0xcbbb9d5dc1059ed8'u64
    ctx.state[1] = 0x629a292a367cd507'u64
    ctx.state[2] = 0x9159015a3070dd17'u64
    ctx.state[3] = 0x152fecd8f70e5939'u64
    ctx.state[4] = 0x67332667ffc00b31'u64
    ctx.state[5] = 0x8eb44a8768581511'u64
    ctx.state[6] = 0xdb0c2e0d64f98fa7'u64
    ctx.state[7] = 0x47b5481dbefa4fa4'u64
  elif K == SHA2_512:
    ctx.state[0] = 0x6a09e667f3bcc908'u64
    ctx.state[1] = 0xbb67ae8584caa73b'u64
    ctx.state[2] = 0x3c6ef372fe94f82b'u64
    ctx.state[3] = 0xa54ff53a5f1d36f1'u64
    ctx.state[4] = 0x510e527fade682d1'u64
    ctx.state[5] = 0x9b05688c2b3e6c1f'u64
    ctx.state[6] = 0x1f83d9abfb41bd6b'u64
    ctx.state[7] = 0x5be0cd19137e2179'u64
  elif K == SHA2_512_224:
    ctx.state[0] = 0x8c3d37c819544da2'u64
    ctx.state[1] = 0x73e1996689dcd4d6'u64
    ctx.state[2] = 0x1dfab7ae32ff9c82'u64
    ctx.state[3] = 0x679dd514582f9fcf'u64
    ctx.state[4] = 0x0f6d2b697bd44da8'u64
    ctx.state[5] = 0x77e36f7304C48942'u64
    ctx.state[6] = 0x3f9d85a86a1d36C8'u64
    ctx.state[7] = 0x1112e6ad91d692a1'u64
  elif K == SHA2_512_256:
    ctx.state[0] = 0x22312194fc2bf72c'u64
    ctx.state[1] = 0x9f555fa3c84c64c2'u64
    ctx.state[2] = 0x2393b86b6f53b151'u64
    ctx.state[3] = 0x963877195940eabd'u64
    ctx.state[4] = 0x96283ee2a88effe3'u64
    ctx.state[5] = 0xbe5e1e2553863992'u64
    ctx.state[6] = 0x2b0199fc2c85b8aa'u64
    ctx.state[7] = 0x0eb72ddC81c52ca2'u64

template sha2InputC[B: static[int], H: static[int], T; K: static SHA2Kind](ctx: var SHA2Ctx[B, H, T, K], input: openArray[uint8]): void {.autoSizeOpt.} =
  let inputLen: int = input.len
  var check: bool = true
  
  if inputLen == 0: check = false

  if check:
    var index: int = ctx.index

    when T is uint64:
      let oldLength: uint64 = ctx.length[0]
      ctx.length[0] += uint64(inputLen)
      if ctx.length[0] < oldLength:
        ctx.length[1] += 1
    elif T is uint32:
      let oldLength: uint32 = ctx.length[0]
      ctx.length[0] += uint32(inputLen)
      if ctx.length[0] < oldLength:
        ctx.length[1] += 1

    let left: int = B - index
    var position: int = 0

    if inputLen >= left:
      if left > 0:
        copyMem(addr ctx.buffer[index], addr input[0], left)
      when T is uint32:
        sha2Transform256(ctx.state, ctx.buffer.toSliceArray(0, 63))
      else:
        sha2Transform512(ctx.state, ctx.buffer.toSliceArray(0, 127))
      position = left
      index = 0

      when T is uint32:
        while position + 64 <= inputLen:
          sha2Transform256(ctx.state, input.toSliceArray(position, position + 63, 64))
          position += 64
      else:
        while position + 128 <= inputLen:
          sha2Transform512(ctx.state, input.toSliceArray(position, position + 127, 128))
          position += 128

    let remain: int = inputLen - position
    if remain > 0:
      copyMem(addr ctx.buffer[index], addr input[position], remain)
      index += remain
    
    ctx.index = index

template sha2FinalC[B: static[int], H: static[int], T; K: static SHA2Kind](ctx: var SHA2Ctx[B, H, T, K]): array[H, uint8] {.autoSizeOpt.} =
  when T is uint64:
    var output: array[H, uint8]
  else:
    var output: array[H, uint8]

  var index: int = ctx.index

  ctx.buffer[index] = 0x80'u8
  index.inc

  const PaddingIndex: int = when T is uint32: 56 elif T is uint64: 112
  let padLen: int = if index <= PaddingIndex: PaddingIndex - index else: B - index

  if index <= PaddingIndex:
    zeroMem(addr ctx.buffer[index], padLen)
  else:
    if padLen > 0:
      zeroMem(addr ctx.buffer[index], padLen)
    when T is uint64:
      sha2Transform512(ctx.state, ctx.buffer.toSliceArray(0, 127))
    elif T is uint32:
      sha2Transform256(ctx.state, ctx.buffer.toSliceArray(0, 63))
    zeroMem(addr ctx.buffer[0], PaddingIndex)

  when T is uint64:
    let bitLength: array[2, uint64] = [(ctx.length[1] shl 3) or (ctx.length[0] shr 61), ctx.length[0] shl 3]
    encodeBE(bitLength.toSliceArray(0, 1), ctx.buffer.toSliceArray(PaddingIndex, B - 1))
    sha2Transform512(ctx.state, ctx.buffer.toSliceArray(0, 127))
  elif T is uint32:
    let bitLength: array[2, uint32] = [(ctx.length[1] shl 3) or (ctx.length[0] shr 29), ctx.length[0] shl 3]
    encodeBE(bitLength.toSliceArray(0, 1), ctx.buffer.toSliceArray(PaddingIndex, B - 1))
    sha2Transform256(ctx.state, ctx.buffer.toSliceArray(0, 63))
  
  when BE:
    copyMem(addr output, addr ctx.state, H)
  else:
    when K == SHA2_224:
      encodeBE(ctx.state.toSliceArray(0, 6), output.toSliceArray(0, 27))
    elif K == SHA2_256:
      encodeBE(ctx.state, output)
    elif K == SHA2_384:
      encodeBE(ctx.state.toSliceArray(0, 5), output.toSliceArray(0, 47))
    elif K == SHA2_512:
      encodeBE(ctx.state, output)
    elif K == SHA2_512_224:
      # var temp: array[32, uint8]
      # encodeBE(ctx.state.toSliceArray(0, 3), temp.toSliceArray(0, 31))
      # copyMem(addr output, addr temp, 28)

      unroll(i, 0, 3):
        unroll(j, 0, 7):
          when (i * 8 + j) < 28:
            output[i * 8 + j] = uint8(ctx.state[i] shr ((7 - j) * 8) and 0xFF'u64)
    elif K == SHA2_512_256:
      # encodeBE(ctx.state.toSliceArray(0, 3), output.toSliceArray(0, 31))
      encodeBE(ctx.state.toSliceArray(0, 3), output.toSliceArray(0, 31))

  output

# export wrappers
when defined(templateOpt):
  template sha2_224Init*(ctx: var SHA2_224Ctx): void = sha2InitC(ctx)
  template sha2_224Input*(ctx: var SHA2_224Ctx, input: openArray[uint8]): void = sha2InputC(ctx, input)
  template sha2_224Final*(ctx: var SHA2_224Ctx): array[28, uint8] = sha2FinalC(ctx)
  template sha2_224One*(input: openArray[uint8]): array[28, uint8] = sha2_224OneC(input)

  template sha2_256Init*(ctx: var SHA2_256Ctx): void = sha2InitC(ctx)
  template sha2_256Input*(ctx: var SHA2_256Ctx, input: openArray[uint8]): void = sha2InputC(ctx, input)
  template sha2_256Final*(ctx: var SHA2_256Ctx): array[32, uint8] = sha2FinalC(ctx)
  template sha2_256One*(input: openArray[uint8]): array[32, uint8] = sha2_256OneC(input)

  template sha2_384Init*(ctx: var SHA2_384Ctx): void = sha2InitC(ctx)
  template sha2_384Input*(ctx: var SHA2_384Ctx, input: openArray[uint8]): void = sha2InputC(ctx, input)
  template sha2_384Final*(ctx: var SHA2_384Ctx): array[48, uint8] = sha2FinalC(ctx)
  template sha2_384One*(input: openArray[uint8]): array[48, uint8] = sha2_384OneC(input)

  template sha2_512Init*(ctx: var SHA2_512Ctx): void = sha2InitC(ctx)
  template sha2_512Input*(ctx: var SHA2_512Ctx, input: openArray[uint8]): void = sha2InputC(ctx, input)
  template sha2_512Final*(ctx: var SHA2_512Ctx): array[64, uint8] = sha2FinalC(ctx)
  template sha2_512One*(input: openArray[uint8]): array[64, uint8] = sha2_512OneC(input)

  template sha2_512_224Init*(ctx: var SHA2_512_224Ctx): void = sha2InitC(ctx)
  template sha2_512_224Input*(ctx: var SHA2_512_224Ctx, input: openArray[uint8]): void = sha2InputC(ctx, input)
  template sha2_512_224Final*(ctx: var SHA2_512_224Ctx): array[28, uint8] = sha2FinalC(ctx)
  template sha2_512_224One*(input: openArray[uint8]): array[28, uint8] = sha2_512_224OneC(input)

  template sha2_512_256Init*(ctx: var SHA2_512_256Ctx): void = sha2InitC(ctx)
  template sha2_512_256Input*(ctx: var SHA2_512_256Ctx, input: openArray[uint8]): void = sha2InputC(ctx, input)
  template sha2_512_256Final*(ctx: var SHA2_512_256Ctx): array[32, uint8] = sha2FinalC(ctx)
  template sha2_512_256One*(input: openArray[uint8]): array[32, uint8] = sha2_512_256OneC(input)

  when Native:
    template sha2_224Init*(ctx: ptr SHA2_224Ctx): void = sha2InitC(ctx[])
    template sha2_224Input*(ctx: ptr SHA2_224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = sha2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template sha2_224Final*(ctx: ptr SHA2_224Ctx, output: ptr array[28, uint8]): void = output[] = sha2FinalC(ctx[])
    template sha2_224One*(output: ptr array[28, uint8], input: ptr UncheckedArray[uint8], inputLen: int): void = output[] = sha2_224OneC(input.toOpenArray(0, inputLen - 1))

    template sha2_256Init*(ctx: ptr SHA2_256Ctx): void = sha2InitC(ctx[])
    template sha2_256Input*(ctx: ptr SHA2_256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = sha2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template sha2_256Final*(ctx: ptr SHA2_256Ctx, output: ptr array[32, uint8]): void = output[] = sha2FinalC(ctx[])
    template sha2_256One*(output: ptr array[32, uint8], input: ptr UncheckedArray[uint8], inputLen: int): void = output[] = sha2_256OneC(input.toOpenArray(0, inputLen - 1))

    template sha2_384Init*(ctx: ptr SHA2_384Ctx): void = sha2InitC(ctx[])
    template sha2_384Input*(ctx: ptr SHA2_384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = sha2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template sha2_384Final*(ctx: ptr SHA2_384Ctx, output: ptr array[48, uint8]): void = output[] = sha2FinalC(ctx[])
    template sha2_384One*(output: ptr array[48, uint8], input: ptr UncheckedArray[uint8], inputLen: int): void = output[] = sha2_384OneC(input.toOpenArray(0, inputLen - 1))

    template sha2_512Init*(ctx: ptr SHA2_512Ctx): void = sha2InitC(ctx[])
    template sha2_512Input*(ctx: ptr SHA2_512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = sha2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template sha2_512Final*(ctx: ptr SHA2_512Ctx, output: ptr array[64, uint8]): void = output[] = sha2FinalC(ctx[])
    template sha2_512One*(output: ptr array[64, uint8], input: ptr UncheckedArray[uint8], inputLen: int): void = output[] = sha2_512OneC(input.toOpenArray(0, inputLen - 1))

    template sha2_512_224Init*(ctx: ptr SHA2_512_224Ctx): void = sha2InitC(ctx[])
    template sha2_512_224Input*(ctx: ptr SHA2_512_224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = sha2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template sha2_512_224Final*(ctx: ptr SHA2_512_224Ctx, output: ptr array[28, uint8]): void = output[] = sha2FinalC(ctx[])
    template sha2_512_224One*(output: ptr array[28, uint8], input: ptr UncheckedArray[uint8], inputLen: int): void = output[] = sha2_512_224OneC(input.toOpenArray(0, inputLen - 1))

    template sha2_512_256Init*(ctx: ptr SHA2_512_256Ctx): void = sha2InitC(ctx[])
    template sha2_512_256Input*(ctx: ptr SHA2_512_256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = sha2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template sha2_512_256Final*(ctx: ptr SHA2_512_256Ctx, output: ptr array[32, uint8]): void = output[] = sha2FinalC(ctx[])
    template sha2_512_256One*(output: ptr array[32, uint8], input: ptr UncheckedArray[uint8], inputLen: int): void = output[] = sha2_512_256OneC(input.toOpenArray(0, inputLen - 1))

else:
  when Native:
    proc sha2_224Init*(ctx: var SHA2_224Ctx): void = sha2InitC(ctx)
    proc sha2_224Input*(ctx: var SHA2_224Ctx, input: openArray[uint8]): void = sha2InputC(ctx, input)
    proc sha2_224Final*(ctx: var SHA2_224Ctx): array[28, uint8] = sha2FinalC(ctx)
    proc sha2_224One*(input: openArray[uint8]): array[28, uint8] = sha2_224OneC(input)

    proc sha2_256Init*(ctx: var SHA2_256Ctx): void = sha2InitC(ctx)
    proc sha2_256Input*(ctx: var SHA2_256Ctx, input: openArray[uint8]): void = sha2InputC(ctx, input)
    proc sha2_256Final*(ctx: var SHA2_256Ctx): array[32, uint8] = sha2FinalC(ctx)
    proc sha2_256One*(input: openArray[uint8]): array[32, uint8] = sha2_256OneC(input)

    proc sha2_384Init*(ctx: var SHA2_384Ctx): void = sha2InitC(ctx)
    proc sha2_384Input*(ctx: var SHA2_384Ctx, input: openArray[uint8]): void = sha2InputC(ctx, input)
    proc sha2_384Final*(ctx: var SHA2_384Ctx): array[48, uint8] = sha2FinalC(ctx)
    proc sha2_384One*(input: openArray[uint8]): array[48, uint8] = sha2_384OneC(input)

    proc sha2_512Init*(ctx: var SHA2_512Ctx): void = sha2InitC(ctx)
    proc sha2_512Input*(ctx: var SHA2_512Ctx, input: openArray[uint8]): void = sha2InputC(ctx, input)
    proc sha2_512Final*(ctx: var SHA2_512Ctx): array[64, uint8] = sha2FinalC(ctx)
    proc sha2_512One*(input: openArray[uint8]): array[64, uint8] = sha2_512OneC(input)

    proc sha2_512_224Init*(ctx: var SHA2_512_224Ctx): void = sha2InitC(ctx)
    proc sha2_512_224Input*(ctx: var SHA2_512_224Ctx, input: openArray[uint8]): void = sha2InputC(ctx, input)
    proc sha2_512_224Final*(ctx: var SHA2_512_224Ctx): array[28, uint8] = sha2FinalC(ctx)
    proc sha2_512_224One*(input: openArray[uint8]): array[28, uint8] = sha2_512_224OneC(input)

    proc sha2_512_256Init*(ctx: var SHA2_512_256Ctx): void = sha2InitC(ctx)
    proc sha2_512_256Input*(ctx: var SHA2_512_256Ctx, input: openArray[uint8]): void = sha2InputC(ctx, input)
    proc sha2_512_256Final*(ctx: var SHA2_512_256Ctx): array[32, uint8] = sha2FinalC(ctx)
    proc sha2_512_256One*(input: openArray[uint8]): array[32, uint8] = sha2_512_256OneC(input)

  when defined(c) or defined(objc):
    proc sha2_224Init*(ctx: ptr SHA2_224Ctx): void {.exportc: "sha2_224Init".} = sha2InitC(ctx[])
    proc sha2_224Input*(ctx: ptr SHA2_224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "sha2_224Input".} = sha2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc sha2_224Final*(ctx: ptr SHA2_224Ctx, output: ptr array[28, uint8]): void {.exportc: "sha2_224Final".} = output[] = sha2FinalC(ctx[])
    proc sha2_224One*(output: ptr array[28, uint8], input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "sha2_224One".} = output[] = sha2_224OneC(input.toOpenArray(0, inputLen - 1))

    proc sha2_256Init*(ctx: ptr SHA2_256Ctx): void {.exportc: "sha2_256Init".} = sha2InitC(ctx[])
    proc sha2_256Input*(ctx: ptr SHA2_256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "sha2_256Input".} = sha2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc sha2_256Final*(ctx: ptr SHA2_256Ctx, output: ptr array[32, uint8]): void {.exportc: "sha2_256Final".} = output[] = sha2FinalC(ctx[])
    proc sha2_256One*(output: ptr array[32, uint8], input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "sha2_256One".} = output[] = sha2_256OneC(input.toOpenArray(0, inputLen - 1))

    proc sha2_384Init*(ctx: ptr SHA2_384Ctx): void {.exportc: "sha2_384Init".} = sha2InitC(ctx[])
    proc sha2_384Input*(ctx: ptr SHA2_384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "sha2_384Input".} = sha2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc sha2_384Final*(ctx: ptr SHA2_384Ctx, output: ptr array[48, uint8]): void {.exportc: "sha2_384Final".} = output[] = sha2FinalC(ctx[])
    proc sha2_384One*(output: ptr array[48, uint8], input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "sha2_384One".} = output[] = sha2_384OneC(input.toOpenArray(0, inputLen - 1))

    proc sha2_512Init*(ctx: ptr SHA2_512Ctx): void {.exportc: "sha2_512Init".} = sha2InitC(ctx[])
    proc sha2_512Input*(ctx: ptr SHA2_512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "sha2_512Input".} = sha2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc sha2_512Final*(ctx: ptr SHA2_512Ctx, output: ptr array[64, uint8]): void {.exportc: "sha2_512Final".} = output[] = sha2FinalC(ctx[])
    proc sha2_512One*(output: ptr array[64, uint8], input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "sha2_512One".} = output[] = sha2_512OneC(input.toOpenArray(0, inputLen - 1))

    proc sha2_512_224Init*(ctx: ptr SHA2_512_224Ctx): void {.exportc: "sha2_512_224Init".} = sha2InitC(ctx[])
    proc sha2_512_224Input*(ctx: ptr SHA2_512_224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "sha2_512_224Input".} = sha2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc sha2_512_224Final*(ctx: ptr SHA2_512_224Ctx, output: ptr array[28, uint8]): void {.exportc: "sha2_512_224Final".} = output[] = sha2FinalC(ctx[])
    proc sha2_512_224One*(output: ptr array[28, uint8], input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "sha2_512_224One".} = output[] = sha2_512_224OneC(input.toOpenArray(0, inputLen - 1))

    proc sha2_512_256Init*(ctx: ptr SHA2_512_256Ctx): void {.exportc: "sha2_512_256Init".} = sha2InitC(ctx[])
    proc sha2_512_256Input*(ctx: ptr SHA2_512_256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "sha2_512_256Input".} = sha2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc sha2_512_256Final*(ctx: ptr SHA2_512_256Ctx, output: ptr array[32, uint8]): void {.exportc: "sha2_512_256Final".} = output[] = sha2FinalC(ctx[])
    proc sha2_512_256One*(output: ptr array[32, uint8], input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "sha2_512_256One".} = output[] = sha2_512_256OneC(input.toOpenArray(0, inputLen - 1))

  elif defined(cpp):
    proc sha2_224Init*(ctx: ptr SHA2_224Ctx): void {.exportcpp: "sha2_224Init".} = sha2InitC(ctx[])
    proc sha2_224Input*(ctx: ptr SHA2_224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "sha2_224Input".} = sha2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc sha2_224Final*(ctx: ptr SHA2_224Ctx, output: ptr array[28, uint8]): void {.exportcpp: "sha2_224Final".} = output[] = sha2FinalC(ctx[])
    proc sha2_224One*(output: ptr array[28, uint8], input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "sha2_224One".} = output[] = sha2_224OneC(input.toOpenArray(0, inputLen - 1))

    proc sha2_256Init*(ctx: ptr SHA2_256Ctx): void {.exportcpp: "sha2_256Init".} = sha2InitC(ctx[])
    proc sha2_256Input*(ctx: ptr SHA2_256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "sha2_256Input".} = sha2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc sha2_256Final*(ctx: ptr SHA2_256Ctx, output: ptr array[32, uint8]): void {.exportcpp: "sha2_256Final".} = output[] = sha2FinalC(ctx[])
    proc sha2_256One*(output: ptr array[32, uint8], input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "sha2_256One".} = output[] = sha2_256OneC(input.toOpenArray(0, inputLen - 1))

    proc sha2_384Init*(ctx: ptr SHA2_384Ctx): void {.exportcpp: "sha2_384Init".} = sha2InitC(ctx[])
    proc sha2_384Input*(ctx: ptr SHA2_384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "sha2_384Input".} = sha2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc sha2_384Final*(ctx: ptr SHA2_384Ctx, output: ptr array[48, uint8]): void {.exportcpp: "sha2_384Final".} = output[] = sha2FinalC(ctx[])
    proc sha2_384One*(output: ptr array[48, uint8], input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "sha2_384One".} = output[] = sha2_384OneC(input.toOpenArray(0, inputLen - 1))

    proc sha2_512Init*(ctx: ptr SHA2_512Ctx): void {.exportcpp: "sha2_512Init".} = sha2InitC(ctx[])
    proc sha2_512Input*(ctx: ptr SHA2_512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "sha2_512Input".} = sha2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc sha2_512Final*(ctx: ptr SHA2_512Ctx, output: ptr array[64, uint8]): void {.exportcpp: "sha2_512Final".} = output[] = sha2FinalC(ctx[])
    proc sha2_512One*(output: ptr array[64, uint8], input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "sha2_512One".} = output[] = sha2_512OneC(input.toOpenArray(0, inputLen - 1))

    proc sha2_512_224Init*(ctx: ptr SHA2_512_224Ctx): void {.exportcpp: "sha2_512_224Init".} = sha2InitC(ctx[])
    proc sha2_512_224Input*(ctx: ptr SHA2_512_224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "sha2_512_224Input".} = sha2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc sha2_512_224Final*(ctx: ptr SHA2_512_224Ctx, output: ptr array[28, uint8]): void {.exportcpp: "sha2_512_224Final".} = output[] = sha2FinalC(ctx[])
    proc sha2_512_224One*(output: ptr array[28, uint8], input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "sha2_512_224One".} = output[] = sha2_512_224OneC(input.toOpenArray(0, inputLen - 1))

    proc sha2_512_256Init*(ctx: ptr SHA2_512_256Ctx): void {.exportcpp: "sha2_512_256Init".} = sha2InitC(ctx[])
    proc sha2_512_256Input*(ctx: ptr SHA2_512_256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "sha2_512_256Input".} = sha2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc sha2_512_256Final*(ctx: ptr SHA2_512_256Ctx, output: ptr array[32, uint8]): void {.exportcpp: "sha2_512_256Final".} = output[] = sha2_512_256FinalC(ctx[])
    proc sha2_512_256One*(output: ptr array[32, uint8], input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "sha2_512_256One".} = output[] = sha2_512_256OneC(input.toOpenArray(0, inputLen - 1))
