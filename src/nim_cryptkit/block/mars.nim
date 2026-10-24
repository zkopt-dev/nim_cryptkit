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

## UNSUPPORTED : THIS CIPHER IS NOT TESTED DON'T USE

const
  SBox: array[512, uint32] = [
    0x09d0c479'u32, 0x28c8ffe0'u32, 0x84aa6c39'u32, 0x9dad7287'u32, 0x7dff9be3'u32, 0xd4268361'u32, 0xc96da1d4'u32, 0x7974cc93'u32,
    0x85d0582e'u32, 0x2a4b5705'u32, 0x1ca16a62'u32, 0xc3bd279d'u32, 0x0f1f25e5'u32, 0x5160372f'u32, 0xc695c1fb'u32, 0x4d7ff1e4'u32,
    0xae5f6bf4'u32, 0x0d72ee46'u32, 0xff23de8a'u32, 0xb1cf8e83'u32, 0xf14902e2'u32, 0x3e981e42'u32, 0x8bf53eb6'u32, 0x7f4bf8ac'u32,
    0x83631f83'u32, 0x25970205'u32, 0x76afe784'u32, 0x3a7931d4'u32, 0x4f846450'u32, 0x5c64c3f6'u32, 0x210a5f18'u32, 0xc6986a26'u32,
    0x28f4e826'u32, 0x3a60a81c'u32, 0xd340a664'u32, 0x7ea820c4'u32, 0x526687c5'u32, 0x7eddd12b'u32, 0x32a11d1d'u32, 0x9c9ef086'u32,
    0x80f6e831'u32, 0xab6f04ad'u32, 0x56fb9b53'u32, 0x8b2e095c'u32, 0xb68556ae'u32, 0xd2250b0d'u32, 0x294a7721'u32, 0xe21fb253'u32,
    0xae136749'u32, 0xe82aae86'u32, 0x93365104'u32, 0x99404a66'u32, 0x78a784dc'u32, 0xb69ba84b'u32, 0x04046793'u32, 0x23db5c1e'u32,
    0x46cae1d6'u32, 0x2fe28134'u32, 0x5a223942'u32, 0x1863cd5b'u32, 0xc190c6e3'u32, 0x07dfb846'u32, 0x6eb88816'u32, 0x2d0dcc4a'u32,
    0xa4ccae59'u32, 0x3798670d'u32, 0xcbfa9493'u32, 0x4f481d45'u32, 0xeafc8ca8'u32, 0xdb1129d6'u32, 0xb0449e20'u32, 0x0f5407fb'u32,
    0x6167d9a8'u32, 0xd1f45763'u32, 0x4daa96c3'u32, 0x3bec5958'u32, 0xababa014'u32, 0xb6ccd201'u32, 0x38d6279f'u32, 0x02682215'u32,
    0x8f376cd5'u32, 0x092c237e'u32, 0xbfc56593'u32, 0x32889d2c'u32, 0x854b3e95'u32, 0x05bb9b43'u32, 0x7dcd5dcd'u32, 0xa02e926c'u32,
    0xfae527e5'u32, 0x36a1c330'u32, 0x3412e1ae'u32, 0xf257f462'u32, 0x3c4f1d71'u32, 0x30a2e809'u32, 0x68e5f551'u32, 0x9c61ba44'u32,
    0x5ded0ab8'u32, 0x75ce09c8'u32, 0x9654f93e'u32, 0x698c0cca'u32, 0x243cb3e4'u32, 0x2b062b97'u32, 0x0f3b8d9e'u32, 0x00e050df'u32,
    0xfc5d6166'u32, 0xe35f9288'u32, 0xc079550d'u32, 0x0591aee8'u32, 0x8e531e74'u32, 0x75fe3578'u32, 0x2f6d829a'u32, 0xf60b21ae'u32,
    0x95e8eb8d'u32, 0x6699486b'u32, 0x901d7d9b'u32, 0xfd6d6e31'u32, 0x1090acef'u32, 0xe0670dd8'u32, 0xdab2e692'u32, 0xcd6d4365'u32,
    0xe5393514'u32, 0x3af345f0'u32, 0x6241fc4d'u32, 0x460da3a3'u32, 0x7bcf3729'u32, 0x8bf1d1e0'u32, 0x14aac070'u32, 0x1587ed55'u32,
    0x3afd7d3e'u32, 0xd2f29e01'u32, 0x29a9d1f6'u32, 0xefb10c53'u32, 0xcf3b870f'u32, 0xb414935c'u32, 0x664465ed'u32, 0x024acac7'u32,
    0x59a744c1'u32, 0x1d2936a7'u32, 0xdc580aa6'u32, 0xcf574ca8'u32, 0x040a7a10'u32, 0x6cd81807'u32, 0x8a98be4c'u32, 0xaccea063'u32,
    0xc33e92b5'u32, 0xd1e0e03d'u32, 0xb322517e'u32, 0x2092bd13'u32, 0x386b2c4a'u32, 0x52e8dd58'u32, 0x58656dfb'u32, 0x50820371'u32,
    0x41811896'u32, 0xe337ef7e'u32, 0xd39fb119'u32, 0xc97f0df6'u32, 0x68fea01b'u32, 0xa150a6e5'u32, 0x55258962'u32, 0xeb6ff41b'u32,
    0xd7c9cd7a'u32, 0xa619cd9e'u32, 0xbcf09576'u32, 0x2672c073'u32, 0xf003fb3c'u32, 0x4ab7a50b'u32, 0x1484126a'u32, 0x487ba9b1'u32,
    0xa64fc9c6'u32, 0xf6957d49'u32, 0x38b06a75'u32, 0xdd805fcd'u32, 0x63d094cf'u32, 0xf51c999e'u32, 0x1aa4d343'u32, 0xb8495294'u32,
    0xce9f8e99'u32, 0xbffcd770'u32, 0xc7c275cc'u32, 0x378453a7'u32, 0x7b21be33'u32, 0x397f41bd'u32, 0x4e94d131'u32, 0x92cc1f98'u32,
    0x5915ea51'u32, 0x99f861b7'u32, 0xc9980a88'u32, 0x1d74fd5f'u32, 0xb0a495f8'u32, 0x614deed0'u32, 0xb5778eea'u32, 0x5941792d'u32,
    0xfa90c1f8'u32, 0x33f824b4'u32, 0xc4965372'u32, 0x3ff6d550'u32, 0x4ca5fec0'u32, 0x8630e964'u32, 0x5b3fbbd6'u32, 0x7da26a48'u32,
    0xb203231a'u32, 0x04297514'u32, 0x2d639306'u32, 0x2eb13149'u32, 0x16a45272'u32, 0x532459a0'u32, 0x8e5f4872'u32, 0xf966c7d9'u32,
    0x07128dc0'u32, 0x0d44db62'u32, 0xafc8d52d'u32, 0x06316131'u32, 0xd838e7ce'u32, 0x1bc41d00'u32, 0x3a2e8c0f'u32, 0xea83837e'u32,
    0xb984737d'u32, 0x13ba4891'u32, 0xc4f8b949'u32, 0xa6d6acb3'u32, 0xa215cdce'u32, 0x8359838b'u32, 0x6bd1aa31'u32, 0xf579dd52'u32,
    0x21b93f93'u32, 0xf5176781'u32, 0x187dfdde'u32, 0xe94aeb76'u32, 0x2b38fd54'u32, 0x431de1da'u32, 0xab394825'u32, 0x9ad3048f'u32,
    0xdfea32aa'u32, 0x659473e3'u32, 0x623f7863'u32, 0xf3346c59'u32, 0xab3ab685'u32, 0x3346a90b'u32, 0x6b56443e'u32, 0xc6de01f8'u32,
    0x8d421fc0'u32, 0x9b0ed10c'u32, 0x88f1a1e9'u32, 0x54c1f029'u32, 0x7dead57b'u32, 0x8d7ba426'u32, 0x4cf5178a'u32, 0x551a7cca'u32,
    0x1a9a5f08'u32, 0xfcd651b9'u32, 0x25605182'u32, 0xe11fc6c3'u32, 0xb6fd9676'u32, 0x337b3027'u32, 0xb7c8eb14'u32, 0x9e5fd030'u32,
    0x6b57e354'u32, 0xad913cf7'u32, 0x7e16688d'u32, 0x58872a69'u32, 0x2c2fc7df'u32, 0xe389ccc6'u32, 0x30738df1'u32, 0x0824a734'u32,
    0xe1797a8b'u32, 0xa4a8d57b'u32, 0x5b5d193b'u32, 0xc8a8309b'u32, 0x73f9a978'u32, 0x73398d32'u32, 0x0f59573e'u32, 0xe9df2b03'u32,
    0xe8a5b6c8'u32, 0x848d0704'u32, 0x98df93c2'u32, 0x720a1dc3'u32, 0x684f259a'u32, 0x943ba848'u32, 0xa6370152'u32, 0x863b5ea3'u32,
    0xd17b978b'u32, 0x6d9b58ef'u32, 0x0a700dd4'u32, 0xa73d36bf'u32, 0x8e6a0829'u32, 0x8695bc14'u32, 0xe35b3447'u32, 0x933ac568'u32,
    0x8894b022'u32, 0x2f511c27'u32, 0xddfbcc3c'u32, 0x006662b6'u32, 0x117c83fe'u32, 0x4e12b414'u32, 0xc2bca766'u32, 0x3a2fec10'u32,
    0xf4562420'u32, 0x55792e2a'u32, 0x46f5d857'u32, 0xceda25ce'u32, 0xc3601d3b'u32, 0x6c00ab46'u32, 0xefac9c28'u32, 0xb3c35047'u32,
    0x611dfee3'u32, 0x257c3207'u32, 0xfdd58482'u32, 0x3b14d84f'u32, 0x23becb64'u32, 0xa075f3a3'u32, 0x088f8ead'u32, 0x07adf158'u32,
    0x7796943c'u32, 0xfacabf3d'u32, 0xc09730cd'u32, 0xf7679969'u32, 0xda44e9ed'u32, 0x2c854c12'u32, 0x35935fa3'u32, 0x2f057d9f'u32,
    0x690624f8'u32, 0x1cb0bafd'u32, 0x7b0dbdc6'u32, 0x810f23bb'u32, 0xfa929a1a'u32, 0x6d969a17'u32, 0x6742979b'u32, 0x74ac7d05'u32,
    0x010e65c4'u32, 0x86a3d963'u32, 0xf907b5a0'u32, 0xd0042bd3'u32, 0x158d7d03'u32, 0x287a8255'u32, 0xbba8366f'u32, 0x096edc33'u32,
    0x21916a7b'u32, 0x77b56b86'u32, 0x951622f9'u32, 0xa6c5e650'u32, 0x8cea17d1'u32, 0xcd8c62bc'u32, 0xa3d63433'u32, 0x358a68fd'u32,
    0x0f9b9d3c'u32, 0xd6aa295b'u32, 0xfe33384a'u32, 0xc000738e'u32, 0xcd67eb2f'u32, 0xe2eb6dc2'u32, 0x97338b02'u32, 0x06c9f246'u32,
    0x419cf1ad'u32, 0x2b83c045'u32, 0x3723f18a'u32, 0xcb5b3089'u32, 0x160bead7'u32, 0x5d494656'u32, 0x35f8a74b'u32, 0x1e4e6c9e'u32,
    0x000399bd'u32, 0x67466880'u32, 0xb4174831'u32, 0xacf423b2'u32, 0xca815ab3'u32, 0x5a6395e7'u32, 0x302a67c5'u32, 0x8bdb446b'u32,
    0x108f8fa4'u32, 0x10223eda'u32, 0x92b8b48b'u32, 0x7f38d0ee'u32, 0xab2701d4'u32, 0x0262d415'u32, 0xaf224a30'u32, 0xb3d88aba'u32,
    0xf8b2c3af'u32, 0xdaf7ef70'u32, 0xcc97d3b7'u32, 0xe9614b6c'u32, 0x2baebff4'u32, 0x70f687cf'u32, 0x386c9156'u32, 0xce092ee5'u32,
    0x01e87da6'u32, 0x6ce91e6a'u32, 0xbb7bcc84'u32, 0xc7922c20'u32, 0x9d3b71fd'u32, 0x060e41c6'u32, 0xd7590f15'u32, 0x4e03bb47'u32,
    0x183c198e'u32, 0x63eeb240'u32, 0x2ddbf49a'u32, 0x6d5cba54'u32, 0x923750af'u32, 0xf9e14236'u32, 0x7838162b'u32, 0x59726c72'u32,
    0x81b66760'u32, 0xbb2926c1'u32, 0x48a0ce0d'u32, 0xa6c0496d'u32, 0xad43507b'u32, 0x718d496a'u32, 0x9df057af'u32, 0x44b1bde6'u32,
    0x054356dc'u32, 0xde7ced35'u32, 0xd51a138b'u32, 0x62088cc9'u32, 0x35830311'u32, 0xc96efca2'u32, 0x686f86ec'u32, 0x8e77cb68'u32,
    0x63e1d6b8'u32, 0xc80f9778'u32, 0x79c491fd'u32, 0x1b4c67f2'u32, 0x72698d7d'u32, 0x5e368c31'u32, 0xf7d95e2e'u32, 0xa1d3493f'u32,
    0xdcd9433e'u32, 0x896f1552'u32, 0x4bc4ca7a'u32, 0xa6d1baf4'u32, 0xa5a96dcc'u32, 0x0bef8b46'u32, 0xa169fda7'u32, 0x74df40b7'u32,
    0x4e208804'u32, 0x9a756607'u32, 0x038e87c8'u32, 0x20211e44'u32, 0x8b7ad4bf'u32, 0xc6403f35'u32, 0x1848e36d'u32, 0x80bdb038'u32,
    0x1e62891c'u32, 0x643d2107'u32, 0xbf04d6f8'u32, 0x21092c8c'u32, 0xf644f389'u32, 0x0778404e'u32, 0x7b78adb8'u32, 0xa2c52d53'u32,
    0x42157abe'u32, 0xa2253e2e'u32, 0x7bf3f4ae'u32, 0x80f594f9'u32, 0x953194e7'u32, 0x77eb92ed'u32, 0xb3816930'u32, 0xda8d9336'u32,
    0xbf447469'u32, 0xf26d9483'u32, 0xee6faed5'u32, 0x71371235'u32, 0xde425f73'u32, 0xb4e59f43'u32, 0x7dbe2d4e'u32, 0x2d37b185'u32,
    0x49dc9a63'u32, 0x98c39d98'u32, 0x1301c9a2'u32, 0x389b1bbf'u32, 0x0c18588d'u32, 0xa421c1ba'u32, 0x7aa3865c'u32, 0x71e08558'u32,
    0x3c5cfcaa'u32, 0x7d239ca4'u32, 0x0297d9dd'u32, 0xd7dc2830'u32, 0x4b37802b'u32, 0x7428ab54'u32, 0xaeee0347'u32, 0x4b3fbb85'u32,
    0x692f2f08'u32, 0x134e578e'u32, 0x36d9e0bf'u32, 0xae8b5fcf'u32, 0xedb93ecf'u32, 0x2b27248e'u32, 0x170eb1ef'u32, 0x7dc57fd6'u32,
    0x1e760f16'u32, 0xb1136601'u32, 0x864e1b9b'u32, 0xd7ea7319'u32, 0x3ab871bd'u32, 0xcfa4d76f'u32, 0xe31bd782'u32, 0x0dbeb469'u32,
    0xabb96061'u32, 0x5370f85d'u32, 0xffb07e37'u32, 0xda30d0fb'u32, 0xebc977b6'u32, 0x0b98b40f'u32, 0x3a4d0fe6'u32, 0xdf4fc26b'u32,
    0x159cf22a'u32, 0xc298d6e2'u32, 0x2b78ef6a'u32, 0x61a94ac0'u32, 0xab561187'u32, 0x14eea0f0'u32, 0xdf0d4164'u32, 0x19af70ee'u32,
  ]

type
  MARSCtx* = object
    roundKey*: array[40, uint32]

template rotateLeftBitsMod[T](x: T, y: T): T =
  let shift: int = int(y and (sizeof(T) * 8 - 1))
  rotateLeftBits(x, shift)

template rotateRightBitsMod[T](x: T, y: T): T =
  let shift: int = int(y and (sizeof(T) * 8 - 1))
  rotateRightBits(x, shift)

template S(a: uint32): uint32 = SBox[int(a and 0x1FF'u32)]
template S0(a: uint32): uint32 = SBox[int(a and 0xFF'u32)]
template S1(a: uint32): uint32 = SBox[int(a and 0xFF'u32) + 256]

template marsInitC(ctx: MARSCtx, key: openArray[uint8]): void =
  var temp: array[15, uint32]

  let words: int = key.len div 4
  for i in 0 ..< words:
    fromBytesLE(key.toSliceArray(i * 4, i * 4 + 3, 4), temp[i])
  temp[words] = uint32(words)

  for j in static(0 ..< 4):
    for i in static(0 .. 14):
      temp[i] = temp[i] xor rotateLeftBits(temp[(i + 8) mod 15] xor temp[(i + 13) mod 15], 3) xor (uint32(4 * i) + j)

    for k in static(0 .. 3):
      for i in static(0 ..< 14):
        temp[i] = rotateLeftBits(temp[i] + SBox[temp[(i + 14) mod 15] mod 512], 9)

    for i in static(0 .. 9):
      ctx.roundKey[10 * j + i] = temp[(4 * i) mod 15]

  for i in countup(5, 35, 2):
    var w = ctx.roundKey[i] or 3
    var m = (not w xor (w shl 1)) and (not w xor (w shr 1)) and 0x7ffffffe'u32
    m = m and (m shr 1); m = m and (m shr 2); m = m and (m shr 4)
    m = m or (m shl 1); m = m or (m shl 2); m = m or (m shl 4)
    m = m and 0x7ffffffc'u32
    w = w xor (rotateLeftBitsMod(Sbox[265 + int(ctx.roundKey[i] and 3)], ctx.roundKey[i - 1]) and m)
    ctx.roundKey[i] = w

template marsEncryptC(ctx: MARSCtx, input, output: slicearray[16, uint8]): void =
  var a, b, c, d: uint32
  fromBytesLE(input.toSliceArray(0, 3), a)
  fromBytesLE(input.toSliceArray(4, 7), b)
  fromBytesLE(input.toSliceArray(8, 11), c)
  fromBytesLE(input.toSliceArray(12, 15), d)
  a += ctx.roundKey[0]; b += ctx.roundKey[1]; c += ctx.roundKey[2]; d += ctx.roundKey[3]
  var l, m, r, t: uint32

  unroll(i, 0, 7):
    b = (b xor S0(a)) + S1(a shr 8)
    c += S0(a shr 16)
    a = rotateRightBits(a, 24)
    d = d xor S1(a)
    when i mod 4 == 0:
      a += d
    elif i mod 4 == 1:
      a += b
    t = a; a = b; b = c; c = d; d = t

  unroll(i, 0, 15):
    t = rotateLeftBits(a, 13)
    r = rotateLeftBits(t * ctx.roundKey[2 * i + 5], 10)
    m = a + ctx.roundKey[2 * i + 4]
    l = rotateLeftBitsMod(S(m) xor rotateRightBits(r, 5) xor r, r)
    c += rotateLeftBitsMod(m, rotateRightBits(r, 5))
    when i < 8:
      b += l
      d = d xor r
    else:
      d += l
      b = b xor r
    a = b; b = c; c = d; d = t

  unroll(i, 0, 7):
    when i mod 4 == 2:
      a -= d
    elif i mod 4 == 3:
      a -= b
    b = b xor S1(a)
    c -= S0(a shr 24)
    t = rotateLeftBits(a, 24)
    d = (d - S1(a shr 16)) xor S0(t)
    a = b; b = c; c = d; d = t

  a -= ctx.roundKey[36]; b -= ctx.roundKey[37]; c -= ctx.roundKey[38]; d -= ctx.roundKey[39]

  toBytesLE(a, output.toSliceArray(0, 3))
  toBytesLE(b, output.toSliceArray(4, 7))
  toBytesLE(c, output.toSliceArray(8, 11))
  toBytesLE(d, output.toSliceArray(12, 15))

template marsDecryptC(ctx: MARSCtx, input, output: slicearray[16, uint8]): void =
  var a, b, c, d: uint32
  fromBytesLE(input.toSliceArray(0, 3), d)
  fromBytesLE(input.toSliceArray(4, 7), c)
  fromBytesLE(input.toSliceArray(8, 11), b)
  fromBytesLE(input.toSliceArray(12, 15), a)
  d += ctx.roundKey[36]; c += ctx.roundKey[37]; b += ctx.roundKey[38]; a += ctx.roundKey[39]
  var l, m, r, t: uint32

  unroll(i, 0, 7):
    t = d; d = c; c = b; b = a; a = t
    t = rotateRightBits(a, 24)
    d = (d xor S0(t)) + S1(a shr 16)
    c += S0(a shr 24)
    b = b xor S1(a)
    when (7 - i) mod 4 == 3: a += b
    elif (7 - i) mod 4 == 2: a += d

  unroll(i, 0, 15):
    t = d; d = c; c = b; b = a; a = t
    r = rotateLeftBits(d * ctx.roundKey[2 * (15 - i) + 5], 10)
    m = d + ctx.roundKey[2 * (15 - i) + 4]
    l = rotateLeftBitsMod(S(m) xor rotateRightBits(r, 5) xor r, r)
    c -= rotateLeftBitsMod(m, rotateRightBits(r, 5))
    when idx < 8:
      b -= l; a = a xor r
    else:
      a -= l; b = b xor r

  unroll(i, 0, 7):
    t = d; d = c; c = b; b = a; a = t
    when (7 - i) mod 4 == 1: a -= b
    elif (7 - i) mod 4 == 0: a -= d
    d = d xor S1(a)
    a = rotateLeftBits(a, 24)
    c -= S0(a shr 16)
    b = (b - S1(a shr 8)) xor S0(a)

  d -= ctx.roundKey[0]; c -= ctx.roundKey[1]; b -= ctx.roundKey[2]; a -= ctx.roundKey[3]

  toBytesLE(d, output.toSliceArray(0, 3))
  toBytesLE(c, output.toSliceArray(4, 7))
  toBytesLE(b, output.toSliceArray(8, 11))
  toBytesLE(a, output.toSliceArray(12, 15))
