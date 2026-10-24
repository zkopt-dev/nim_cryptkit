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

# CPu's bits
const
  Bits* = sizeof(int) * 8

const
  # lea rounds constant
  LEA128Rounds*: int = 24
  LEA192Rounds*: int = 28
  LEA256Rounds*: int = 32

const 
  Delta: array[8, array[36, uint32]] = [
    [
      0xc3efe9db'u32, 0x87dfd3b7'u32, 0x0fbfa76f'u32, 0x1f7f4ede'u32, 0x3efe9dbc'u32, 0x7dfd3b78'u32, 0xfbfa76f0'u32, 0xf7f4ede1'u32,
      0xefe9dbc3'u32, 0xdfd3b787'u32, 0xbfa76f0f'u32, 0x7f4ede1f'u32, 0xfe9dbc3e'u32, 0xfd3b787d'u32, 0xfa76f0fb'u32, 0xf4ede1f7'u32,
      0xe9dbc3ef'u32, 0xd3b787df'u32, 0xa76f0fbf'u32, 0x4ede1f7f'u32, 0x9dbc3efe'u32, 0x3b787dfd'u32, 0x76f0fbfa'u32, 0xede1f7f4'u32,
      0xdbc3efe9'u32, 0xb787dfd3'u32, 0x6f0fbfa7'u32, 0xde1f7f4e'u32, 0xbc3efe9d'u32, 0x787dfd3b'u32, 0xf0fbfa76'u32, 0xe1f7f4eD'u32,
      0xc3efe9db'u32, 0x87dfd3b7'u32, 0x0fbfa76f'u32, 0x1f7f4ede'u32
    ],
    [
      0x44626b02'u32, 0x88c4d604'u32, 0x1189ac09'u32, 0x23135812'u32, 0x4626b024'u32, 0x8c4d6048'u32, 0x189ac091'u32, 0x31358122'u32,
      0x626b0244'u32, 0xc4d60488'u32, 0x89ac0911'u32, 0x13581223'u32, 0x26b02446'u32, 0x4d60488c'u32, 0x9ac09118'u32, 0x35812231'u32,
      0x6b024462'u32, 0xd60488c4'u32, 0xac091189'u32, 0x58122313'u32, 0xb0244626'u32, 0x60488c4d'u32, 0xc091189a'u32, 0x81223135'u32,
      0x0244626b'u32, 0x0488c4d6'u32, 0x091189ac'u32, 0x12231358'u32, 0x244626b0'u32, 0x488c4d60'u32, 0x91189ac0'u32, 0x22313581'u32,
      0x44626b02'u32, 0x88c4d604'u32, 0x1189ac09'u32, 0x23135812'u32
    ],
    [
      0x79e27c8a'u32, 0xf3c4f914'u32, 0xe789f229'u32, 0xcf13e453'u32, 0x9e27c8a7'u32, 0x3c4f914f'u32, 0x789f229e'u32, 0xf13e453c'u32,
      0xe27c8a79'u32, 0xc4f914f3'u32, 0x89f229e7'u32, 0x13e453cf'u32, 0x27c8a79e'u32, 0x4f914f3c'u32, 0x9f229e78'u32, 0x3e453cf1'u32,
      0x7c8a79e2'u32, 0xf914f3c4'u32, 0xf229e789'u32, 0xe453cf13'u32, 0xc8a79e27'u32, 0x914f3c4f'u32, 0x229e789f'u32, 0x453cf13e'u32,
      0x8a79e27c'u32, 0x14f3c4f9'u32, 0x29e789f2'u32, 0x53cf13e4'u32, 0xa79e27c8'u32, 0x4f3c4f91'u32, 0x9e789f22'u32, 0x3cf13e45'u32,
      0x79e27c8a'u32, 0xf3c4f914'u32, 0xe789f229'u32, 0xcf13e453'u32
    ],
    [
      0x78df30ec'u32, 0xf1be61d8'u32, 0xe37cc3b1'u32, 0xc6f98763'u32, 0x8df30ec7'u32, 0x1be61d8f'u32, 0x37cc3b1e'u32, 0x6f98763c'u32,
      0xdf30ec78'u32, 0xbe61d8f1'u32, 0x7cc3b1e3'u32, 0xf98763c6'u32, 0xf30ec78d'u32, 0xe61d8f1b'u32, 0xcc3b1e37'u32, 0x98763c6f'u32,
      0x30ec78df'u32, 0x61d8f1be'u32, 0xc3b1e37c'u32, 0x8763c6f9'u32, 0x0ec78df3'u32, 0x1d8f1be6'u32, 0x3b1e37cc'u32, 0x763c6f98'u32,
      0xec78df30'u32, 0xd8f1be61'u32, 0xb1e37cc3'u32, 0x63c6f987'u32, 0xc78df30e'u32, 0x8f1be61d'u32, 0x1e37cc3b'u32, 0x3c6f9876'u32,
      0x78df30ec'u32, 0xf1be61d8'u32, 0xe37cc3b1'u32, 0xc6f98763'u32
    ],
    [
      0x715ea49e'u32, 0xe2bd493c'u32, 0xc57a9279'u32, 0x8af524f3'u32, 0x15ea49e7'u32, 0x2bd493ce'u32, 0x57a9279c'u32, 0xaf524f38'u32,
      0x5ea49e71'u32, 0xbd493ce2'u32, 0x7a9279c5'u32, 0xf524f38a'u32, 0xea49e715'u32, 0xd493ce2b'u32, 0xa9279c57'u32, 0x524f38af'u32,
      0xa49e715e'u32, 0x493ce2bd'u32, 0x9279c57a'u32, 0x24f38af5'u32, 0x49e715ea'u32, 0x93ce2bd4'u32, 0x279c57a9'u32, 0x4f38af52'u32,
      0x9e715ea4'u32, 0x3ce2bd49'u32, 0x79c57a92'u32, 0xf38af524'u32, 0xe715ea49'u32, 0xce2bd493'u32, 0x9c57a927'u32, 0x38af524f'u32,
      0x715ea49e'u32, 0xe2bd493c'u32, 0xc57a9279'u32, 0x8af524f3'u32
    ],
    [
      0xc785da0a'u32, 0x8f0bb415'u32, 0x1e17682b'u32, 0x3c2ed056'u32, 0x785da0ac'u32, 0xf0bb4158'u32, 0xe17682b1'u32, 0xc2ed0563'u32,
      0x85da0ac7'u32, 0x0bb4158f'u32, 0x17682b1e'u32, 0x2ed0563c'u32, 0x5da0ac78'u32, 0xbb4158f0'u32, 0x7682b1e1'u32, 0xed0563c2'u32,
      0xda0ac785'u32, 0xb4158f0b'u32, 0x682b1e17'u32, 0xd0563c2e'u32, 0xa0ac785d'u32, 0x4158f0bb'u32, 0x82b1e176'u32, 0x0563c2ed'u32,
      0x0ac785da'u32, 0x158f0bb4'u32, 0x2b1e1768'u32, 0x563c2ed0'u32, 0xac785da0'u32, 0x58f0bb41'u32, 0xb1e17682'u32, 0x63c2ed05'u32,
      0xc785da0a'u32, 0x8f0bb415'u32, 0x1e17682b'u32, 0x3c2ed056'u32
    ],
    [
      0xe04ef22a'u32, 0xc09de455'u32, 0x813bc8ab'u32, 0x02779157'u32, 0x04ef22ae'u32, 0x09de455c'u32, 0x13bc8ab8'u32, 0x27791570'u32,
      0x4ef22ae0'u32, 0x9de455c0'u32, 0x3bc8ab81'u32, 0x77915702'u32, 0xef22ae04'u32, 0xde455c09'u32, 0xbc8ab813'u32, 0x79157027'u32,
      0xf22ae04e'u32, 0xe455c09d'u32, 0xc8ab813b'u32, 0x91570277'u32, 0x22ae04ef'u32, 0x455c09de'u32, 0x8ab813bc'u32, 0x15702779'u32,
      0x2ae04ef2'u32, 0x55c09de4'u32, 0xab813bc8'u32, 0x57027791'u32, 0xae04ef22'u32, 0x5c09de45'u32, 0xb813bc8a'u32, 0x70277915'u32,
      0xe04ef22a'u32, 0xc09de455'u32, 0x813bc8ab'u32, 0x02779157'u32
    ],
    [
      0xe5c40957'u32, 0xcb8812af'u32, 0x9710255f'u32, 0x2e204abf'u32, 0x5c40957e'u32, 0xb8812afc'u32, 0x710255f9'u32, 0xe204abf2'u32,
      0xc40957e5'u32, 0x8812afcb'u32, 0x10255f97'u32, 0x204abf2e'u32, 0x40957e5c'u32, 0x812afcb8'u32, 0x0255f971'u32, 0x04abf2e2'u32,
      0x0957e5c4'u32, 0x12afcb88'u32, 0x255f9710'u32, 0x4abf2e20'u32, 0x957e5c40'u32, 0x2afcb881'u32, 0x55f97102'u32, 0xabf2e204'u32,
      0x57e5c409'u32, 0xafcb8812'u32, 0x5f971025'u32, 0xbf2e204a'u32, 0x7e5c4095'u32, 0xfcb8812a'u32, 0xf9710255'u32, 0xf2e204ab'u32,
      0xe5c40957'u32, 0xcb8812af'u32, 0x9710255f'u32, 0x2e204abf'u32
    ]
  ]

# get key size
template roundKey(keyBits: static int): static int =
  when keyBits == 128:
    24 * 6
  elif keyBits == 192:
    28 * 6
  else:
    32 * 6


type
  # lea generic context
  # set roundKey's length with keyBits
  LEACtx*[keyBits: static int] = object
    roundKey*: array[roundKey(keyBits), uint32]

  # lea 128/192/256 context
  LEA128Ctx* {.exportc: "LEA128Ctx", completeStruct.} = LEACtx[128]
  LEA192Ctx* {.exportc: "LEA192Ctx", completeStruct.} = LEACtx[192]
  LEA256Ctx* {.exportc: "LEA256Ctx", completeStruct.} = LEACtx[256]

# get key size
template keySize*[keyBits: static int](ctx: LEACtx[keyBits]): static int =
  static: doAssert keyBits == 128 or keyBits == 192 or keyBits == 256
  when keyBits == 128:
    16
  elif keyBits == 192:
    24
  elif keyBits == 256:
    32
  else:
    0

# get round number
template roundNumber*[keyBits: static int](ctx: LEACtx[keyBits]): static int =
  static: doAssert keyBits == 128 or keyBits == 192 or keyBits == 256
  when keyBits == 128:
    24
  elif keyBits == 192:
    28
  elif keyBits == 256:
    32
  else:
    0

template blockSize*[keyBits: static int](ctx: LEACtx[keyBits]): static int =
  static: doAssert keyBits == 128 or keyBits == 192 or keyBits == 256
  16

# lea init core
template leaInitC*[N, keyBits: static int](ctx: var LEACtx[keyBits], key: slicearray[N, uint8]): void {.autoSizeOpt.} =
  # check key size
  static: doAssert N == 16 or N == 24 or N == 32

  # declare and initialize buffer
  const wordsKeyLen: int = keySize(ctx) div 4
  when BE:
    var keyU32: array[wordsKeyLen, uint32]
    decodeLE(key, keyU32.toSliceArray(0, wordsKeyLen - 1))
  else:
    var keyU32: ptr array[wordsKeyLen, uint32] = cast[ptr array[wordsKeyLen, uint32]](addr key[0])

  when keyBits == 128:
    ctx.roundKey[0] = rotateLeftBits(keyU32[0] + Delta[0][0], 1)
    unroll(i, 1, 23):
      ctx.roundKey[i * 6] = rotateLeftBits(ctx.roundKey[(i - 1) * 6] + Delta[i and 3][i], 1)

    ctx.roundKey[1] = rotateLeftBits(keyU32[1] + Delta[0][1], 3)
    ctx.roundKey[3] = ctx.roundKey[1]
    ctx.roundKey[5] = ctx.roundKey[1]
    unroll(i, 1, 23):
      ctx.roundKey[i * 6 + 1] = rotateLeftBits(ctx.roundKey[(i - 1) * 6 + 1] + Delta[i and 3][i + 1], 3)
      ctx.roundKey[i * 6 + 3] = ctx.roundKey[i * 6 + 1]
      ctx.roundKey[i * 6 + 5] = ctx.roundKey[i * 6 + 1]
    
    ctx.roundKey[2] = rotateLeftBits(keyU32[2] + Delta[0][2], 6)
    unroll(i, 1, 23):
      ctx.roundKey[i * 6 + 2] = rotateLeftBits(ctx.roundKey[(i - 1) * 6 + 2] + Delta[i and 3][i + 2], 6)

    ctx.roundKey[4] = rotateLeftBits(keyU32[3] + Delta[0][3], 11)
    unroll(i, 1, 23):
      ctx.roundKey[i * 6 + 4] = rotateLeftBits(ctx.roundKey[(i - 1) * 6 + 4] + Delta[i and 3][i + 3], 11)
  elif keyBits == 192:
    ctx.roundKey[0] = rotateLeftBits(keyU32[0] + Delta[0][0], 1)
    unroll(i, 1, 27):
      ctx.roundKey[i * 6] = rotateLeftBits(ctx.roundKey[(i - 1) * 6] + Delta[i mod 6][i], 1)

    ctx.roundKey[1] = rotateLeftBits(keyU32[1] + Delta[0][1], 3)
    unroll(i, 1, 27):
      ctx.roundKey[i * 6 + 1] = rotateLeftBits(ctx.roundKey[(i - 1) * 6 + 1] + Delta[i mod 6][i + 1], 3)

    ctx.roundKey[2] = rotateLeftBits(keyU32[2] + Delta[0][2], 6)
    unroll(i, 1, 27):
      ctx.roundKey[i * 6 + 2] = rotateLeftBits(ctx.roundKey[(i - 1) * 6 + 2] + Delta[i mod 6][i + 2], 6)

    ctx.roundKey[3] = rotateLeftBits(keyU32[3] + Delta[0][3], 11)
    unroll(i, 1, 27):
      ctx.roundKey[i * 6 + 3] = rotateLeftBits(ctx.roundKey[(i - 1) * 6 + 3] + Delta[i mod 6][i + 3], 11)

    ctx.roundKey[4] = rotateLeftBits(keyU32[4] + Delta[0][4], 13)
    unroll(i, 1, 27):
      ctx.roundKey[i * 6 + 4] = rotateLeftBits(ctx.roundKey[(i - 1) * 6 + 4] + Delta[i mod 6][i + 4], 13)

    ctx.roundKey[5] = rotateLeftBits(keyU32[5] + Delta[0][5], 17)
    unroll(i, 1, 27):
      ctx.roundKey[i * 6 + 5] = rotateLeftBits(ctx.roundKey[(i - 1) * 6 + 5] + Delta[i mod 6][i + 5], 17)
  elif keyBits == 256:
    ctx.roundKey[0] = rotateLeftBits(keyU32[0] + Delta[0][0], 1)
    ctx.roundKey[8] = rotateLeftBits(ctx.roundKey[0] + Delta[1][3], 6)
    ctx.roundKey[16] = rotateLeftBits(ctx.roundKey[8] + Delta[2][6], 13)
    ctx.roundKey[24] = rotateLeftBits(ctx.roundKey[16] + Delta[4][4], 1)
    ctx.roundKey[32] = rotateLeftBits(ctx.roundKey[24] + Delta[5][7], 6)
    ctx.roundKey[40] = rotateLeftBits(ctx.roundKey[32] + Delta[6][10], 13)
    ctx.roundKey[48] = rotateLeftBits(ctx.roundKey[40] + Delta[0][8], 1)
    ctx.roundKey[56] = rotateLeftBits(ctx.roundKey[48] + Delta[1][11], 6)
    ctx.roundKey[64] = rotateLeftBits(ctx.roundKey[56] + Delta[2][14], 13)
    ctx.roundKey[72] = rotateLeftBits(ctx.roundKey[64] + Delta[4][12], 1)
    ctx.roundKey[80] = rotateLeftBits(ctx.roundKey[72] + Delta[5][15], 6)
    ctx.roundKey[88] = rotateLeftBits(ctx.roundKey[80] + Delta[6][18], 13)
    ctx.roundKey[96] = rotateLeftBits(ctx.roundKey[88] + Delta[0][16], 1)
    ctx.roundKey[104] = rotateLeftBits(ctx.roundKey[96] + Delta[1][19], 6)
    ctx.roundKey[112] = rotateLeftBits(ctx.roundKey[104] + Delta[2][22], 13)
    ctx.roundKey[120] = rotateLeftBits(ctx.roundKey[112] + Delta[4][20], 1)
    ctx.roundKey[128] = rotateLeftBits(ctx.roundKey[120] + Delta[5][23], 6)
    ctx.roundKey[136] = rotateLeftBits(ctx.roundKey[128] + Delta[6][26], 13)
    ctx.roundKey[144] = rotateLeftBits(ctx.roundKey[136] + Delta[0][24], 1)
    ctx.roundKey[152] = rotateLeftBits(ctx.roundKey[144] + Delta[1][27], 6)
    ctx.roundKey[160] = rotateLeftBits(ctx.roundKey[152] + Delta[2][30], 13)
    ctx.roundKey[168] = rotateLeftBits(ctx.roundKey[160] + Delta[4][28], 1)
    ctx.roundKey[176] = rotateLeftBits(ctx.roundKey[168] + Delta[5][31], 6)
    ctx.roundKey[184] = rotateLeftBits(ctx.roundKey[176] + Delta[6][2], 13)

    ctx.roundKey[1] = rotateLeftBits(keyU32[1] + Delta[0][1], 3)
    ctx.roundKey[9] = rotateLeftBits(ctx.roundKey[1] + Delta[1][4], 11)
    ctx.roundKey[17] = rotateLeftBits(ctx.roundKey[9] + Delta[2][7], 17)
    ctx.roundKey[25] = rotateLeftBits(ctx.roundKey[17] + Delta[4][5], 3)
    ctx.roundKey[33] = rotateLeftBits(ctx.roundKey[25] + Delta[5][8], 11)
    ctx.roundKey[41] = rotateLeftBits(ctx.roundKey[33] + Delta[6][11], 17)
    ctx.roundKey[49] = rotateLeftBits(ctx.roundKey[41] + Delta[0][9], 3)
    ctx.roundKey[57] = rotateLeftBits(ctx.roundKey[49] + Delta[1][12], 11)
    ctx.roundKey[65] = rotateLeftBits(ctx.roundKey[57] + Delta[2][15], 17)
    ctx.roundKey[73] = rotateLeftBits(ctx.roundKey[65] + Delta[4][13], 3)
    ctx.roundKey[81] = rotateLeftBits(ctx.roundKey[73] + Delta[5][16], 11)
    ctx.roundKey[89] = rotateLeftBits(ctx.roundKey[81] + Delta[6][19], 17)
    ctx.roundKey[97] = rotateLeftBits(ctx.roundKey[89] + Delta[0][17], 3)
    ctx.roundKey[105] = rotateLeftBits(ctx.roundKey[97] + Delta[1][20], 11)
    ctx.roundKey[113] = rotateLeftBits(ctx.roundKey[105] + Delta[2][23], 17)
    ctx.roundKey[121] = rotateLeftBits(ctx.roundKey[113] + Delta[4][21], 3)
    ctx.roundKey[129] = rotateLeftBits(ctx.roundKey[121] + Delta[5][24], 11)
    ctx.roundKey[137] = rotateLeftBits(ctx.roundKey[129] + Delta[6][27], 17)
    ctx.roundKey[145] = rotateLeftBits(ctx.roundKey[137] + Delta[0][25], 3)
    ctx.roundKey[153] = rotateLeftBits(ctx.roundKey[145] + Delta[1][28], 11)
    ctx.roundKey[161] = rotateLeftBits(ctx.roundKey[153] + Delta[2][31], 17)
    ctx.roundKey[169] = rotateLeftBits(ctx.roundKey[161] + Delta[4][29], 3)
    ctx.roundKey[177] = rotateLeftBits(ctx.roundKey[169] + Delta[5][0], 11)
    ctx.roundKey[185] = rotateLeftBits(ctx.roundKey[177] + Delta[6][3], 17)
       
    ctx.roundKey[2] = rotateLeftBits(keyU32[2] + Delta[0][2], 6)
    ctx.roundKey[10] = rotateLeftBits(ctx.roundKey[2] + Delta[1][5], 13)
    ctx.roundKey[18] = rotateLeftBits(ctx.roundKey[10] + Delta[3][3], 1)
    ctx.roundKey[26] = rotateLeftBits(ctx.roundKey[18] + Delta[4][6], 6)
    ctx.roundKey[34] = rotateLeftBits(ctx.roundKey[26] + Delta[5][9], 13)
    ctx.roundKey[42] = rotateLeftBits(ctx.roundKey[34] + Delta[7][7], 1)
    ctx.roundKey[50] = rotateLeftBits(ctx.roundKey[42] + Delta[0][10], 6)
    ctx.roundKey[58] = rotateLeftBits(ctx.roundKey[50] + Delta[1][13], 13)
    ctx.roundKey[66] = rotateLeftBits(ctx.roundKey[58] + Delta[3][11], 1)
    ctx.roundKey[74] = rotateLeftBits(ctx.roundKey[66] + Delta[4][14], 6)
    ctx.roundKey[82] = rotateLeftBits(ctx.roundKey[74] + Delta[5][17], 13)
    ctx.roundKey[90] = rotateLeftBits(ctx.roundKey[82] + Delta[7][15], 1)
    ctx.roundKey[98] = rotateLeftBits(ctx.roundKey[90] + Delta[0][18], 6)
    ctx.roundKey[106] = rotateLeftBits(ctx.roundKey[98] + Delta[1][21], 13)
    ctx.roundKey[114] = rotateLeftBits(ctx.roundKey[106] + Delta[3][19], 1)
    ctx.roundKey[122] = rotateLeftBits(ctx.roundKey[114] + Delta[4][22], 6)
    ctx.roundKey[130] = rotateLeftBits(ctx.roundKey[122] + Delta[5][25], 13)
    ctx.roundKey[138] = rotateLeftBits(ctx.roundKey[130] + Delta[7][23], 1)
    ctx.roundKey[146] = rotateLeftBits(ctx.roundKey[138] + Delta[0][26], 6)
    ctx.roundKey[154] = rotateLeftBits(ctx.roundKey[146] + Delta[1][29], 13)
    ctx.roundKey[162] = rotateLeftBits(ctx.roundKey[154] + Delta[3][27], 1)
    ctx.roundKey[170] = rotateLeftBits(ctx.roundKey[162] + Delta[4][30], 6)
    ctx.roundKey[178] = rotateLeftBits(ctx.roundKey[170] + Delta[5][1], 13)
    ctx.roundKey[186] = rotateLeftBits(ctx.roundKey[178] + Delta[7][31], 1)
    
    ctx.roundKey[3] = rotateLeftBits(keyU32[3] + Delta[0][3], 11)
    ctx.roundKey[11] = rotateLeftBits(ctx.roundKey[3] + Delta[1][6], 17)
    ctx.roundKey[19] = rotateLeftBits(ctx.roundKey[11] + Delta[3][4], 3)
    ctx.roundKey[27] = rotateLeftBits(ctx.roundKey[19] + Delta[4][7], 11)
    ctx.roundKey[35] = rotateLeftBits(ctx.roundKey[27] + Delta[5][10], 17)
    ctx.roundKey[43] = rotateLeftBits(ctx.roundKey[35] + Delta[7][8], 3)
    ctx.roundKey[51] = rotateLeftBits(ctx.roundKey[43] + Delta[0][11], 11)
    ctx.roundKey[59] = rotateLeftBits(ctx.roundKey[51] + Delta[1][14], 17)
    ctx.roundKey[67] = rotateLeftBits(ctx.roundKey[59] + Delta[3][12], 3)
    ctx.roundKey[75] = rotateLeftBits(ctx.roundKey[67] + Delta[4][15], 11)
    ctx.roundKey[83] = rotateLeftBits(ctx.roundKey[75] + Delta[5][18], 17)
    ctx.roundKey[91] = rotateLeftBits(ctx.roundKey[83] + Delta[7][16], 3)
    ctx.roundKey[99] = rotateLeftBits(ctx.roundKey[91] + Delta[0][19], 11)
    ctx.roundKey[107] = rotateLeftBits(ctx.roundKey[99] + Delta[1][22], 17)
    ctx.roundKey[115] = rotateLeftBits(ctx.roundKey[107] + Delta[3][20], 3)
    ctx.roundKey[123] = rotateLeftBits(ctx.roundKey[115] + Delta[4][23], 11)
    ctx.roundKey[131] = rotateLeftBits(ctx.roundKey[123] + Delta[5][26], 17)
    ctx.roundKey[139] = rotateLeftBits(ctx.roundKey[131] + Delta[7][24], 3)
    ctx.roundKey[147] = rotateLeftBits(ctx.roundKey[139] + Delta[0][27], 11)
    ctx.roundKey[155] = rotateLeftBits(ctx.roundKey[147] + Delta[1][30], 17)
    ctx.roundKey[163] = rotateLeftBits(ctx.roundKey[155] + Delta[3][28], 3)
    ctx.roundKey[171] = rotateLeftBits(ctx.roundKey[163] + Delta[4][31], 11)
    ctx.roundKey[179] = rotateLeftBits(ctx.roundKey[171] + Delta[5][2], 17)
    ctx.roundKey[187] = rotateLeftBits(ctx.roundKey[179] + Delta[7][0], 3)
    
    ctx.roundKey[4] = rotateLeftBits(keyU32[4] + Delta[0][4], 13)
    ctx.roundKey[12] = rotateLeftBits(ctx.roundKey[4] + Delta[2][2], 1)
    ctx.roundKey[20] = rotateLeftBits(ctx.roundKey[12] + Delta[3][5], 6)
    ctx.roundKey[28] = rotateLeftBits(ctx.roundKey[20] + Delta[4][8], 13)
    ctx.roundKey[36] = rotateLeftBits(ctx.roundKey[28] + Delta[6][6], 1)
    ctx.roundKey[44] = rotateLeftBits(ctx.roundKey[36] + Delta[7][9], 6)
    ctx.roundKey[52] = rotateLeftBits(ctx.roundKey[44] + Delta[0][12], 13)
    ctx.roundKey[60] = rotateLeftBits(ctx.roundKey[52] + Delta[2][10], 1)
    ctx.roundKey[68] = rotateLeftBits(ctx.roundKey[60] + Delta[3][13], 6)
    ctx.roundKey[76] = rotateLeftBits(ctx.roundKey[68] + Delta[4][16], 13)
    ctx.roundKey[84] = rotateLeftBits(ctx.roundKey[76] + Delta[6][14], 1)
    ctx.roundKey[92] = rotateLeftBits(ctx.roundKey[84] + Delta[7][17], 6)
    ctx.roundKey[100] = rotateLeftBits(ctx.roundKey[92] + Delta[0][20], 13)
    ctx.roundKey[108] = rotateLeftBits(ctx.roundKey[100] + Delta[2][18], 1)
    ctx.roundKey[116] = rotateLeftBits(ctx.roundKey[108] + Delta[3][21], 6)
    ctx.roundKey[124] = rotateLeftBits(ctx.roundKey[116] + Delta[4][24], 13)
    ctx.roundKey[132] = rotateLeftBits(ctx.roundKey[124] + Delta[6][22], 1)
    ctx.roundKey[140] = rotateLeftBits(ctx.roundKey[132] + Delta[7][25], 6)
    ctx.roundKey[148] = rotateLeftBits(ctx.roundKey[140] + Delta[0][28], 13)
    ctx.roundKey[156] = rotateLeftBits(ctx.roundKey[148] + Delta[2][26], 1)
    ctx.roundKey[164] = rotateLeftBits(ctx.roundKey[156] + Delta[3][29], 6)
    ctx.roundKey[172] = rotateLeftBits(ctx.roundKey[164] + Delta[4][0], 13)
    ctx.roundKey[180] = rotateLeftBits(ctx.roundKey[172] + Delta[6][30], 1)
    ctx.roundKey[188] = rotateLeftBits(ctx.roundKey[180] + Delta[7][1], 6)
    
    ctx.roundKey[5] = rotateLeftBits(keyU32[5] + Delta[0][5], 17)
    ctx.roundKey[13] = rotateLeftBits(ctx.roundKey[5] + Delta[2][3], 3)
    ctx.roundKey[21] = rotateLeftBits(ctx.roundKey[13] + Delta[3][6], 11)
    ctx.roundKey[29] = rotateLeftBits(ctx.roundKey[21] + Delta[4][9], 17)
    ctx.roundKey[37] = rotateLeftBits(ctx.roundKey[29] + Delta[6][7], 3)
    ctx.roundKey[45] = rotateLeftBits(ctx.roundKey[37] + Delta[7][10], 11)
    ctx.roundKey[53] = rotateLeftBits(ctx.roundKey[45] + Delta[0][13], 17)
    ctx.roundKey[61] = rotateLeftBits(ctx.roundKey[53] + Delta[2][11], 3)
    ctx.roundKey[69] = rotateLeftBits(ctx.roundKey[61] + Delta[3][14], 11)
    ctx.roundKey[77] = rotateLeftBits(ctx.roundKey[69] + Delta[4][17], 17)
    ctx.roundKey[85] = rotateLeftBits(ctx.roundKey[77] + Delta[6][15], 3)
    ctx.roundKey[93] = rotateLeftBits(ctx.roundKey[85] + Delta[7][18], 11)
    ctx.roundKey[101] = rotateLeftBits(ctx.roundKey[93] + Delta[0][21], 17)
    ctx.roundKey[109] = rotateLeftBits(ctx.roundKey[101] + Delta[2][19], 3)
    ctx.roundKey[117] = rotateLeftBits(ctx.roundKey[109] + Delta[3][22], 11)
    ctx.roundKey[125] = rotateLeftBits(ctx.roundKey[117] + Delta[4][25], 17)
    ctx.roundKey[133] = rotateLeftBits(ctx.roundKey[125] + Delta[6][23], 3)
    ctx.roundKey[141] = rotateLeftBits(ctx.roundKey[133] + Delta[7][26], 11)
    ctx.roundKey[149] = rotateLeftBits(ctx.roundKey[141] + Delta[0][29], 17)
    ctx.roundKey[157] = rotateLeftBits(ctx.roundKey[149] + Delta[2][27], 3)
    ctx.roundKey[165] = rotateLeftBits(ctx.roundKey[157] + Delta[3][30], 11)
    ctx.roundKey[173] = rotateLeftBits(ctx.roundKey[165] + Delta[4][1], 17)
    ctx.roundKey[181] = rotateLeftBits(ctx.roundKey[173] + Delta[6][31], 3)
    ctx.roundKey[189] = rotateLeftBits(ctx.roundKey[181] + Delta[7][2], 11)
    
    ctx.roundKey[6] = rotateLeftBits(keyU32[6] + Delta[1][1], 1)
    ctx.roundKey[14] = rotateLeftBits(ctx.roundKey[6] + Delta[2][4], 6)
    ctx.roundKey[22] = rotateLeftBits(ctx.roundKey[14] + Delta[3][7], 13)
    ctx.roundKey[30] = rotateLeftBits(ctx.roundKey[22] + Delta[5][5], 1)
    ctx.roundKey[38] = rotateLeftBits(ctx.roundKey[30] + Delta[6][8], 6)
    ctx.roundKey[46] = rotateLeftBits(ctx.roundKey[38] + Delta[7][11], 13)
    ctx.roundKey[54] = rotateLeftBits(ctx.roundKey[46] + Delta[1][9], 1)
    ctx.roundKey[62] = rotateLeftBits(ctx.roundKey[54] + Delta[2][12], 6)
    ctx.roundKey[70] = rotateLeftBits(ctx.roundKey[62] + Delta[3][15], 13)
    ctx.roundKey[78] = rotateLeftBits(ctx.roundKey[70] + Delta[5][13], 1)
    ctx.roundKey[86] = rotateLeftBits(ctx.roundKey[78] + Delta[6][16], 6)
    ctx.roundKey[94] = rotateLeftBits(ctx.roundKey[86] + Delta[7][19], 13)
    ctx.roundKey[102] = rotateLeftBits(ctx.roundKey[94] + Delta[1][17], 1)
    ctx.roundKey[110] = rotateLeftBits(ctx.roundKey[102] + Delta[2][20], 6)
    ctx.roundKey[118] = rotateLeftBits(ctx.roundKey[110] + Delta[3][23], 13)
    ctx.roundKey[126] = rotateLeftBits(ctx.roundKey[118] + Delta[5][21], 1)
    ctx.roundKey[134] = rotateLeftBits(ctx.roundKey[126] + Delta[6][24], 6)
    ctx.roundKey[142] = rotateLeftBits(ctx.roundKey[134] + Delta[7][27], 13)
    ctx.roundKey[150] = rotateLeftBits(ctx.roundKey[142] + Delta[1][25], 1)
    ctx.roundKey[158] = rotateLeftBits(ctx.roundKey[150] + Delta[2][28], 6)
    ctx.roundKey[166] = rotateLeftBits(ctx.roundKey[158] + Delta[3][31], 13)
    ctx.roundKey[174] = rotateLeftBits(ctx.roundKey[166] + Delta[5][29], 1)
    ctx.roundKey[182] = rotateLeftBits(ctx.roundKey[174] + Delta[6][0], 6)
    ctx.roundKey[190] = rotateLeftBits(ctx.roundKey[182] + Delta[7][3], 13) 
    
    ctx.roundKey[7] = rotateLeftBits(keyU32[7] + Delta[1][2], 3)
    ctx.roundKey[15] = rotateLeftBits(ctx.roundKey[7] + Delta[2][5], 11)
    ctx.roundKey[23] = rotateLeftBits(ctx.roundKey[15] + Delta[3][8], 17)
    ctx.roundKey[31] = rotateLeftBits(ctx.roundKey[23] + Delta[5][6], 3)
    ctx.roundKey[39] = rotateLeftBits(ctx.roundKey[31] + Delta[6][9], 11)
    ctx.roundKey[47] = rotateLeftBits(ctx.roundKey[39] + Delta[7][12], 17)
    ctx.roundKey[55] = rotateLeftBits(ctx.roundKey[47] + Delta[1][10], 3)
    ctx.roundKey[63] = rotateLeftBits(ctx.roundKey[55] + Delta[2][13], 11)
    ctx.roundKey[71] = rotateLeftBits(ctx.roundKey[63] + Delta[3][16], 17)
    ctx.roundKey[79] = rotateLeftBits(ctx.roundKey[71] + Delta[5][14], 3)
    ctx.roundKey[87] = rotateLeftBits(ctx.roundKey[79] + Delta[6][17], 11)
    ctx.roundKey[95] = rotateLeftBits(ctx.roundKey[87] + Delta[7][20], 17)
    ctx.roundKey[103] = rotateLeftBits(ctx.roundKey[95] + Delta[1][18], 3)
    ctx.roundKey[111] = rotateLeftBits(ctx.roundKey[103] + Delta[2][21], 11)
    ctx.roundKey[119] = rotateLeftBits(ctx.roundKey[111] + Delta[3][24], 17)
    ctx.roundKey[127] = rotateLeftBits(ctx.roundKey[119] + Delta[5][22], 3)
    ctx.roundKey[135] = rotateLeftBits(ctx.roundKey[127] + Delta[6][25], 11)
    ctx.roundKey[143] = rotateLeftBits(ctx.roundKey[135] + Delta[7][28], 17)
    ctx.roundKey[151] = rotateLeftBits(ctx.roundKey[143] + Delta[1][26], 3)
    ctx.roundKey[159] = rotateLeftBits(ctx.roundKey[151] + Delta[2][29], 11)
    ctx.roundKey[167] = rotateLeftBits(ctx.roundKey[159] + Delta[3][0], 17)
    ctx.roundKey[175] = rotateLeftBits(ctx.roundKey[167] + Delta[5][30], 3)
    ctx.roundKey[183] = rotateLeftBits(ctx.roundKey[175] + Delta[6][1], 11)
    ctx.roundKey[191] = rotateLeftBits(ctx.roundKey[183] + Delta[7][4], 17)

# lea encrypt core
template leaEncryptC[keyBits: static int](ctx: LEACtx[keyBits], input, output: slicearray[16, uint8]): void {.autoSizeOpt.} =
  # delcare temporal registers
  var temp0, temp1, temp2, temp3: uint32

  # decode input to temp by little endian
  fromBytesLE(input.toSliceArray(0, 3), temp0)
  fromBytesLE(input.toSliceArray(4, 7), temp1)
  fromBytesLE(input.toSliceArray(8, 11), temp2)
  fromBytesLE(input.toSliceArray(12, 15), temp3)

  temp3 = rotateRightBits((temp2 xor ctx.roundKey[4]) + (temp3 xor ctx.roundKey[5]), 3)
  temp2 = rotateRightBits((temp1 xor ctx.roundKey[2]) + (temp2 xor ctx.roundKey[3]), 5)
  temp1 = rotateLeftBits((temp0 xor ctx.roundKey[0]) + (temp1 xor ctx.roundKey[1]), 9)

  temp0 = rotateRightBits((temp3 xor ctx.roundKey[10]) + (temp0 xor ctx.roundKey[11]), 3)
  temp3 = rotateRightBits((temp2 xor ctx.roundKey[8]) + (temp3 xor ctx.roundKey[9]), 5)
  temp2 = rotateLeftBits((temp1 xor ctx.roundKey[6]) + (temp2 xor ctx.roundKey[7]), 9)

  temp1 = rotateRightBits((temp0 xor ctx.roundKey[16]) + (temp1 xor ctx.roundKey[17]), 3)
  temp0 = rotateRightBits((temp3 xor ctx.roundKey[14]) + (temp0 xor ctx.roundKey[15]), 5)
  temp3 = rotateLeftBits((temp2 xor ctx.roundKey[12]) + (temp3 xor ctx.roundKey[13]), 9)

  temp2 = rotateRightBits((temp1 xor ctx.roundKey[22]) + (temp2 xor ctx.roundKey[23]), 3)
  temp1 = rotateRightBits((temp0 xor ctx.roundKey[20]) + (temp1 xor ctx.roundKey[21]), 5)
  temp0 = rotateLeftBits((temp3 xor ctx.roundKey[18]) + (temp0 xor ctx.roundKey[19]), 9)

  temp3 = rotateRightBits((temp2 xor ctx.roundKey[28]) + (temp3 xor ctx.roundKey[29]), 3)
  temp2 = rotateRightBits((temp1 xor ctx.roundKey[26]) + (temp2 xor ctx.roundKey[27]), 5)
  temp1 = rotateLeftBits((temp0 xor ctx.roundKey[24]) + (temp1 xor ctx.roundKey[25]), 9)

  temp0 = rotateRightBits((temp3 xor ctx.roundKey[34]) + (temp0 xor ctx.roundKey[35]), 3)
  temp3 = rotateRightBits((temp2 xor ctx.roundKey[32]) + (temp3 xor ctx.roundKey[33]), 5)
  temp2 = rotateLeftBits((temp1 xor ctx.roundKey[30]) + (temp2 xor ctx.roundKey[31]), 9)

  temp1 = rotateRightBits((temp0 xor ctx.roundKey[40]) + (temp1 xor ctx.roundKey[41]), 3)
  temp0 = rotateRightBits((temp3 xor ctx.roundKey[38]) + (temp0 xor ctx.roundKey[39]), 5)
  temp3 = rotateLeftBits((temp2 xor ctx.roundKey[36]) + (temp3 xor ctx.roundKey[37]), 9)

  temp2 = rotateRightBits((temp1 xor ctx.roundKey[46]) + (temp2 xor ctx.roundKey[47]), 3)
  temp1 = rotateRightBits((temp0 xor ctx.roundKey[44]) + (temp1 xor ctx.roundKey[45]), 5)
  temp0 = rotateLeftBits((temp3 xor ctx.roundKey[42]) + (temp0 xor ctx.roundKey[43]), 9)
  
  temp3 = rotateRightBits((temp2 xor ctx.roundKey[52]) + (temp3 xor ctx.roundKey[53]), 3)
  temp2 = rotateRightBits((temp1 xor ctx.roundKey[50]) + (temp2 xor ctx.roundKey[51]), 5)
  temp1 = rotateLeftBits((temp0 xor ctx.roundKey[48]) + (temp1 xor ctx.roundKey[49]), 9)

  temp0 = rotateRightBits((temp3 xor ctx.roundKey[58]) + (temp0 xor ctx.roundKey[59]), 3)
  temp3 = rotateRightBits((temp2 xor ctx.roundKey[56]) + (temp3 xor ctx.roundKey[57]), 5)
  temp2 = rotateLeftBits((temp1 xor ctx.roundKey[54]) + (temp2 xor ctx.roundKey[55]), 9)

  temp1 = rotateRightBits((temp0 xor ctx.roundKey[64]) + (temp1 xor ctx.roundKey[65]), 3)
  temp0 = rotateRightBits((temp3 xor ctx.roundKey[62]) + (temp0 xor ctx.roundKey[63]), 5)
  temp3 = rotateLeftBits((temp2 xor ctx.roundKey[60]) + (temp3 xor ctx.roundKey[61]), 9)

  temp2 = rotateRightBits((temp1 xor ctx.roundKey[70]) + (temp2 xor ctx.roundKey[71]), 3)
  temp1 = rotateRightBits((temp0 xor ctx.roundKey[68]) + (temp1 xor ctx.roundKey[69]), 5)
  temp0 = rotateLeftBits((temp3 xor ctx.roundKey[66]) + (temp0 xor ctx.roundKey[67]), 9)
  
  temp3 = rotateRightBits((temp2 xor ctx.roundKey[76]) + (temp3 xor ctx.roundKey[77]), 3)
  temp2 = rotateRightBits((temp1 xor ctx.roundKey[74]) + (temp2 xor ctx.roundKey[75]), 5)
  temp1 = rotateLeftBits((temp0 xor ctx.roundKey[72]) + (temp1 xor ctx.roundKey[73]), 9)

  temp0 = rotateRightBits((temp3 xor ctx.roundKey[82]) + (temp0 xor ctx.roundKey[83]), 3)
  temp3 = rotateRightBits((temp2 xor ctx.roundKey[80]) + (temp3 xor ctx.roundKey[81]), 5)
  temp2 = rotateLeftBits((temp1 xor ctx.roundKey[78]) + (temp2 xor ctx.roundKey[79]), 9)

  temp1 = rotateRightBits((temp0 xor ctx.roundKey[88]) + (temp1 xor ctx.roundKey[89]), 3)
  temp0 = rotateRightBits((temp3 xor ctx.roundKey[86]) + (temp0 xor ctx.roundKey[87]), 5)
  temp3 = rotateLeftBits((temp2 xor ctx.roundKey[84]) + (temp3 xor ctx.roundKey[85]), 9)

  temp2 = rotateRightBits((temp1 xor ctx.roundKey[94]) + (temp2 xor ctx.roundKey[95]), 3)
  temp1 = rotateRightBits((temp0 xor ctx.roundKey[92]) + (temp1 xor ctx.roundKey[93]), 5)
  temp0 = rotateLeftBits((temp3 xor ctx.roundKey[90]) + (temp0 xor ctx.roundKey[91]), 9)
  
  temp3 = rotateRightBits((temp2 xor ctx.roundKey[100]) + (temp3 xor ctx.roundKey[101]), 3)
  temp2 = rotateRightBits((temp1 xor ctx.roundKey[98]) + (temp2 xor ctx.roundKey[99]), 5)
  temp1 = rotateLeftBits((temp0 xor ctx.roundKey[96]) + (temp1 xor ctx.roundKey[97]), 9)

  temp0 = rotateRightBits((temp3 xor ctx.roundKey[106]) + (temp0 xor ctx.roundKey[107]), 3)
  temp3 = rotateRightBits((temp2 xor ctx.roundKey[104]) + (temp3 xor ctx.roundKey[105]), 5)
  temp2 = rotateLeftBits((temp1 xor ctx.roundKey[102]) + (temp2 xor ctx.roundKey[103]), 9)

  temp1 = rotateRightBits((temp0 xor ctx.roundKey[112]) + (temp1 xor ctx.roundKey[113]), 3)
  temp0 = rotateRightBits((temp3 xor ctx.roundKey[110]) + (temp0 xor ctx.roundKey[111]), 5)
  temp3 = rotateLeftBits((temp2 xor ctx.roundKey[108]) + (temp3 xor ctx.roundKey[109]), 9)

  temp2 = rotateRightBits((temp1 xor ctx.roundKey[118]) + (temp2 xor ctx.roundKey[119]), 3)
  temp1 = rotateRightBits((temp0 xor ctx.roundKey[116]) + (temp1 xor ctx.roundKey[117]), 5)
  temp0 = rotateLeftBits((temp3 xor ctx.roundKey[114]) + (temp0 xor ctx.roundKey[115]), 9)
  
  temp3 = rotateRightBits((temp2 xor ctx.roundKey[124]) + (temp3 xor ctx.roundKey[125]), 3)
  temp2 = rotateRightBits((temp1 xor ctx.roundKey[122]) + (temp2 xor ctx.roundKey[123]), 5)
  temp1 = rotateLeftBits((temp0 xor ctx.roundKey[120]) + (temp1 xor ctx.roundKey[121]), 9)

  temp0 = rotateRightBits((temp3 xor ctx.roundKey[130]) + (temp0 xor ctx.roundKey[131]), 3)
  temp3 = rotateRightBits((temp2 xor ctx.roundKey[128]) + (temp3 xor ctx.roundKey[129]), 5)
  temp2 = rotateLeftBits((temp1 xor ctx.roundKey[126]) + (temp2 xor ctx.roundKey[127]), 9)

  temp1 = rotateRightBits((temp0 xor ctx.roundKey[136]) + (temp1 xor ctx.roundKey[137]), 3)
  temp0 = rotateRightBits((temp3 xor ctx.roundKey[134]) + (temp0 xor ctx.roundKey[135]), 5)
  temp3 = rotateLeftBits((temp2 xor ctx.roundKey[132]) + (temp3 xor ctx.roundKey[133]), 9)

  temp2 = rotateRightBits((temp1 xor ctx.roundKey[142]) + (temp2 xor ctx.roundKey[143]), 3)
  temp1 = rotateRightBits((temp0 xor ctx.roundKey[140]) + (temp1 xor ctx.roundKey[141]), 5)
  temp0 = rotateLeftBits((temp3 xor ctx.roundKey[138]) + (temp0 xor ctx.roundKey[139]), 9)

  when keyBits > 128:
    temp3 = rotateRightBits((temp2 xor ctx.roundKey[148]) + (temp3 xor ctx.roundKey[149]), 3)
    temp2 = rotateRightBits((temp1 xor ctx.roundKey[146]) + (temp2 xor ctx.roundKey[147]), 5)
    temp1 = rotateLeftBits((temp0 xor ctx.roundKey[144]) + (temp1 xor ctx.roundKey[145]), 9)

    temp0 = rotateRightBits((temp3 xor ctx.roundKey[154]) + (temp0 xor ctx.roundKey[155]), 3)
    temp3 = rotateRightBits((temp2 xor ctx.roundKey[152]) + (temp3 xor ctx.roundKey[153]), 5)
    temp2 = rotateLeftBits((temp1 xor ctx.roundKey[150]) + (temp2 xor ctx.roundKey[151]), 9)

    temp1 = rotateRightBits((temp0 xor ctx.roundKey[160]) + (temp1 xor ctx.roundKey[161]), 3)
    temp0 = rotateRightBits((temp3 xor ctx.roundKey[158]) + (temp0 xor ctx.roundKey[159]), 5)
    temp3 = rotateLeftBits((temp2 xor ctx.roundKey[156]) + (temp3 xor ctx.roundKey[157]), 9)

    temp2 = rotateRightBits((temp1 xor ctx.roundKey[166]) + (temp2 xor ctx.roundKey[167]), 3)
    temp1 = rotateRightBits((temp0 xor ctx.roundKey[164]) + (temp1 xor ctx.roundKey[165]), 5)
    temp0 = rotateLeftBits((temp3 xor ctx.roundKey[162]) + (temp0 xor ctx.roundKey[163]), 9)
  
  when keyBits > 192:
    temp3 = rotateRightBits((temp2 xor ctx.roundKey[172]) + (temp3 xor ctx.roundKey[173]), 3)
    temp2 = rotateRightBits((temp1 xor ctx.roundKey[170]) + (temp2 xor ctx.roundKey[171]), 5)
    temp1 = rotateLeftBits((temp0 xor ctx.roundKey[168]) + (temp1 xor ctx.roundKey[169]), 9)

    temp0 = rotateRightBits((temp3 xor ctx.roundKey[178]) + (temp0 xor ctx.roundKey[179]), 3)
    temp3 = rotateRightBits((temp2 xor ctx.roundKey[176]) + (temp3 xor ctx.roundKey[177]), 5)
    temp2 = rotateLeftBits((temp1 xor ctx.roundKey[174]) + (temp2 xor ctx.roundKey[175]), 9)

    temp1 = rotateRightBits((temp0 xor ctx.roundKey[184]) + (temp1 xor ctx.roundKey[185]), 3)
    temp0 = rotateRightBits((temp3 xor ctx.roundKey[182]) + (temp0 xor ctx.roundKey[183]), 5)
    temp3 = rotateLeftBits((temp2 xor ctx.roundKey[180]) + (temp3 xor ctx.roundKey[181]), 9)

    temp2 = rotateRightBits((temp1 xor ctx.roundKey[190]) + (temp2 xor ctx.roundKey[191]), 3)
    temp1 = rotateRightBits((temp0 xor ctx.roundKey[188]) + (temp1 xor ctx.roundKey[189]), 5)
    temp0 = rotateLeftBits((temp3 xor ctx.roundKey[186]) + (temp0 xor ctx.roundKey[187]), 9)

  # encode temp to output by little endian
  toBytesLE(temp0, output.toSliceArray(0, 3))
  toBytesLE(temp1, output.toSliceArray(4, 7))
  toBytesLE(temp2, output.toSliceArray(8, 11))
  toBytesLE(temp3, output.toSliceArray(12, 15))

template leaDecryptC*[keyBits: static int](ctx: LEACtx[keyBits], input, output: slicearray[16, uint8]): void {.autoSizeOpt.} =
  # delcare temporal registers
  var temp0, temp1, temp2, temp3: uint32

  # decode input to temp by little endian
  fromBytesLE(input.toSliceArray(0, 3), temp0)
  fromBytesLE(input.toSliceArray(4, 7), temp1)
  fromBytesLE(input.toSliceArray(8, 11), temp2)
  fromBytesLE(input.toSliceArray(12, 15), temp3)

  when keyBits > 192:
    temp0 = (rotateRightBits(temp0, 9) - (temp3 xor ctx.roundKey[186])) xor ctx.roundKey[187]
    temp1 = (rotateLeftBits(temp1, 5) - (temp0 xor ctx.roundKey[188])) xor ctx.roundKey[189]
    temp2 = (rotateLeftBits(temp2, 3) - (temp1 xor ctx.roundKey[190])) xor ctx.roundKey[191]

    temp3 = (rotateRightBits(temp3, 9) - (temp2 xor ctx.roundKey[180])) xor ctx.roundKey[181]
    temp0 = (rotateLeftBits(temp0, 5) - (temp3 xor ctx.roundKey[182])) xor ctx.roundKey[183]
    temp1 = (rotateLeftBits(temp1, 3) - (temp0 xor ctx.roundKey[184])) xor ctx.roundKey[185]

    temp2 = (rotateRightBits(temp2, 9) - (temp1 xor ctx.roundKey[174])) xor ctx.roundKey[175]
    temp3 = (rotateLeftBits(temp3, 5) - (temp2 xor ctx.roundKey[176])) xor ctx.roundKey[177]
    temp0 = (rotateLeftBits(temp0, 3) - (temp3 xor ctx.roundKey[178])) xor ctx.roundKey[179]

    temp1 = (rotateRightBits(temp1, 9) - (temp0 xor ctx.roundKey[168])) xor ctx.roundKey[169]
    temp2 = (rotateLeftBits(temp2, 5) - (temp1 xor ctx.roundKey[170])) xor ctx.roundKey[171]
    temp3 = (rotateLeftBits(temp3, 3) - (temp2 xor ctx.roundKey[172])) xor ctx.roundKey[173]
  
  when keyBits > 128:
    temp0 = (rotateRightBits(temp0, 9) - (temp3 xor ctx.roundKey[162])) xor ctx.roundKey[163]
    temp1 = (rotateLeftBits(temp1, 5) - (temp0 xor ctx.roundKey[164])) xor ctx.roundKey[165]
    temp2 = (rotateLeftBits(temp2, 3) - (temp1 xor ctx.roundKey[166])) xor ctx.roundKey[167]

    temp3 = (rotateRightBits(temp3, 9) - (temp2 xor ctx.roundKey[156])) xor ctx.roundKey[157]
    temp0 = (rotateLeftBits(temp0, 5) - (temp3 xor ctx.roundKey[158])) xor ctx.roundKey[159]
    temp1 = (rotateLeftBits(temp1, 3) - (temp0 xor ctx.roundKey[160])) xor ctx.roundKey[161]

    temp2 = (rotateRightBits(temp2, 9) - (temp1 xor ctx.roundKey[150])) xor ctx.roundKey[151]
    temp3 = (rotateLeftBits(temp3, 5) - (temp2 xor ctx.roundKey[152])) xor ctx.roundKey[153]
    temp0 = (rotateLeftBits(temp0, 3) - (temp3 xor ctx.roundKey[154])) xor ctx.roundKey[155]

    temp1 = (rotateRightBits(temp1, 9) - (temp0 xor ctx.roundKey[144])) xor ctx.roundKey[145]
    temp2 = (rotateLeftBits(temp2, 5) - (temp1 xor ctx.roundKey[146])) xor ctx.roundKey[147]
    temp3 = (rotateLeftBits(temp3, 3) - (temp2 xor ctx.roundKey[148])) xor ctx.roundKey[149]
  
  temp0 = (rotateRightBits(temp0, 9) - (temp3 xor ctx.roundKey[138])) xor ctx.roundKey[139]
  temp1 = (rotateLeftBits(temp1, 5) - (temp0 xor ctx.roundKey[140])) xor ctx.roundKey[141]
  temp2 = (rotateLeftBits(temp2, 3) - (temp1 xor ctx.roundKey[142])) xor ctx.roundKey[143]

  temp3 = (rotateRightBits(temp3, 9) - (temp2 xor ctx.roundKey[132])) xor ctx.roundKey[133]
  temp0 = (rotateLeftBits(temp0, 5) - (temp3 xor ctx.roundKey[134])) xor ctx.roundKey[135]
  temp1 = (rotateLeftBits(temp1, 3) - (temp0 xor ctx.roundKey[136])) xor ctx.roundKey[137]

  temp2 = (rotateRightBits(temp2, 9) - (temp1 xor ctx.roundKey[126])) xor ctx.roundKey[127]
  temp3 = (rotateLeftBits(temp3, 5) - (temp2 xor ctx.roundKey[128])) xor ctx.roundKey[129]
  temp0 = (rotateLeftBits(temp0, 3) - (temp3 xor ctx.roundKey[130])) xor ctx.roundKey[131]

  temp1 = (rotateRightBits(temp1, 9) - (temp0 xor ctx.roundKey[120])) xor ctx.roundKey[121]
  temp2 = (rotateLeftBits(temp2, 5) - (temp1 xor ctx.roundKey[122])) xor ctx.roundKey[123]
  temp3 = (rotateLeftBits(temp3, 3) - (temp2 xor ctx.roundKey[124])) xor ctx.roundKey[125]
  
  temp0 = (rotateRightBits(temp0, 9) - (temp3 xor ctx.roundKey[114])) xor ctx.roundKey[115]
  temp1 = (rotateLeftBits(temp1, 5) - (temp0 xor ctx.roundKey[116])) xor ctx.roundKey[117]
  temp2 = (rotateLeftBits(temp2, 3) - (temp1 xor ctx.roundKey[118])) xor ctx.roundKey[119]

  temp3 = (rotateRightBits(temp3, 9) - (temp2 xor ctx.roundKey[108])) xor ctx.roundKey[109]
  temp0 = (rotateLeftBits(temp0, 5) - (temp3 xor ctx.roundKey[110])) xor ctx.roundKey[111]
  temp1 = (rotateLeftBits(temp1, 3) - (temp0 xor ctx.roundKey[112])) xor ctx.roundKey[113]

  temp2 = (rotateRightBits(temp2, 9) - (temp1 xor ctx.roundKey[102])) xor ctx.roundKey[103]
  temp3 = (rotateLeftBits(temp3, 5) - (temp2 xor ctx.roundKey[104])) xor ctx.roundKey[105]
  temp0 = (rotateLeftBits(temp0, 3) - (temp3 xor ctx.roundKey[106])) xor ctx.roundKey[107]

  temp1 = (rotateRightBits(temp1, 9) - (temp0 xor ctx.roundKey[96])) xor ctx.roundKey[97]
  temp2 = (rotateLeftBits(temp2, 5) - (temp1 xor ctx.roundKey[98])) xor ctx.roundKey[99]
  temp3 = (rotateLeftBits(temp3, 3) - (temp2 xor ctx.roundKey[100])) xor ctx.roundKey[101]

  temp0 = (rotateRightBits(temp0, 9) - (temp3 xor ctx.roundKey[90])) xor ctx.roundKey[91]
  temp1 = (rotateLeftBits(temp1, 5) - (temp0 xor ctx.roundKey[92])) xor ctx.roundKey[93]
  temp2 = (rotateLeftBits(temp2, 3) - (temp1 xor ctx.roundKey[94])) xor ctx.roundKey[95]

  temp3 = (rotateRightBits(temp3, 9) - (temp2 xor ctx.roundKey[84])) xor ctx.roundKey[85]
  temp0 = (rotateLeftBits(temp0, 5) - (temp3 xor ctx.roundKey[86])) xor ctx.roundKey[87]
  temp1 = (rotateLeftBits(temp1, 3) - (temp0 xor ctx.roundKey[88])) xor ctx.roundKey[89]

  temp2 = (rotateRightBits(temp2, 9) - (temp1 xor ctx.roundKey[78])) xor ctx.roundKey[79]
  temp3 = (rotateLeftBits(temp3, 5) - (temp2 xor ctx.roundKey[80])) xor ctx.roundKey[81]
  temp0 = (rotateLeftBits(temp0, 3) - (temp3 xor ctx.roundKey[82])) xor ctx.roundKey[83]

  temp1 = (rotateRightBits(temp1, 9) - (temp0 xor ctx.roundKey[72])) xor ctx.roundKey[73]
  temp2 = (rotateLeftBits(temp2, 5) - (temp1 xor ctx.roundKey[74])) xor ctx.roundKey[75]
  temp3 = (rotateLeftBits(temp3, 3) - (temp2 xor ctx.roundKey[76])) xor ctx.roundKey[77]

  temp0 = (rotateRightBits(temp0, 9) - (temp3 xor ctx.roundKey[66])) xor ctx.roundKey[67]
  temp1 = (rotateLeftBits(temp1, 5) - (temp0 xor ctx.roundKey[68])) xor ctx.roundKey[69]
  temp2 = (rotateLeftBits(temp2, 3) - (temp1 xor ctx.roundKey[70])) xor ctx.roundKey[71]

  temp3 = (rotateRightBits(temp3, 9) - (temp2 xor ctx.roundKey[60])) xor ctx.roundKey[61]
  temp0 = (rotateLeftBits(temp0, 5) - (temp3 xor ctx.roundKey[62])) xor ctx.roundKey[63]
  temp1 = (rotateLeftBits(temp1, 3) - (temp0 xor ctx.roundKey[64])) xor ctx.roundKey[65]

  temp2 = (rotateRightBits(temp2, 9) - (temp1 xor ctx.roundKey[54])) xor ctx.roundKey[55]
  temp3 = (rotateLeftBits(temp3, 5) - (temp2 xor ctx.roundKey[56])) xor ctx.roundKey[57]
  temp0 = (rotateLeftBits(temp0, 3) - (temp3 xor ctx.roundKey[58])) xor ctx.roundKey[59]

  temp1 = (rotateRightBits(temp1, 9) - (temp0 xor ctx.roundKey[48])) xor ctx.roundKey[49]
  temp2 = (rotateLeftBits(temp2, 5) - (temp1 xor ctx.roundKey[50])) xor ctx.roundKey[51]
  temp3 = (rotateLeftBits(temp3, 3) - (temp2 xor ctx.roundKey[52])) xor ctx.roundKey[53]
  
  temp0 = (rotateRightBits(temp0, 9) - (temp3 xor ctx.roundKey[42])) xor ctx.roundKey[43]
  temp1 = (rotateLeftBits(temp1, 5) - (temp0 xor ctx.roundKey[44])) xor ctx.roundKey[45]
  temp2 = (rotateLeftBits(temp2, 3) - (temp1 xor ctx.roundKey[46])) xor ctx.roundKey[47]

  temp3 = (rotateRightBits(temp3, 9) - (temp2 xor ctx.roundKey[36])) xor ctx.roundKey[37]
  temp0 = (rotateLeftBits(temp0, 5) - (temp3 xor ctx.roundKey[38])) xor ctx.roundKey[39]
  temp1 = (rotateLeftBits(temp1, 3) - (temp0 xor ctx.roundKey[40])) xor ctx.roundKey[41]

  temp2 = (rotateRightBits(temp2, 9) - (temp1 xor ctx.roundKey[30])) xor ctx.roundKey[31]
  temp3 = (rotateLeftBits(temp3, 5) - (temp2 xor ctx.roundKey[32])) xor ctx.roundKey[33]
  temp0 = (rotateLeftBits(temp0, 3) - (temp3 xor ctx.roundKey[34])) xor ctx.roundKey[35]

  temp1 = (rotateRightBits(temp1, 9) - (temp0 xor ctx.roundKey[24])) xor ctx.roundKey[25]
  temp2 = (rotateLeftBits(temp2, 5) - (temp1 xor ctx.roundKey[26])) xor ctx.roundKey[27]
  temp3 = (rotateLeftBits(temp3, 3) - (temp2 xor ctx.roundKey[28])) xor ctx.roundKey[29]
  
  temp0 = (rotateRightBits(temp0, 9) - (temp3 xor ctx.roundKey[18])) xor ctx.roundKey[19]
  temp1 = (rotateLeftBits(temp1, 5) - (temp0 xor ctx.roundKey[20])) xor ctx.roundKey[21]
  temp2 = (rotateLeftBits(temp2, 3) - (temp1 xor ctx.roundKey[22])) xor ctx.roundKey[23]

  temp3 = (rotateRightBits(temp3, 9) - (temp2 xor ctx.roundKey[12])) xor ctx.roundKey[13]
  temp0 = (rotateLeftBits(temp0, 5) - (temp3 xor ctx.roundKey[14])) xor ctx.roundKey[15]
  temp1 = (rotateLeftBits(temp1, 3) - (temp0 xor ctx.roundKey[16])) xor ctx.roundKey[17]

  temp2 = (rotateRightBits(temp2, 9) - (temp1 xor ctx.roundKey[6])) xor ctx.roundKey[7]
  temp3 = (rotateLeftBits(temp3, 5) - (temp2 xor ctx.roundKey[8])) xor ctx.roundKey[9]
  temp0 = (rotateLeftBits(temp0, 3) - (temp3 xor ctx.roundKey[10])) xor ctx.roundKey[11]

  temp1 = (rotateRightBits(temp1, 9) - (temp0 xor ctx.roundKey[0])) xor ctx.roundKey[1]
  temp2 = (rotateLeftBits(temp2, 5) - (temp1 xor ctx.roundKey[2])) xor ctx.roundKey[3]
  temp3 = (rotateLeftBits(temp3, 3) - (temp2 xor ctx.roundKey[4])) xor ctx.roundKey[5]

  # encode temp to output by little endian
  toBytesLE(temp0, output.toSliceArray(0, 3))
  toBytesLE(temp1, output.toSliceArray(4, 7))
  toBytesLE(temp2, output.toSliceArray(8, 11))
  toBytesLE(temp3, output.toSliceArray(12, 15))

when defined(templateOpt):
  template lea128Init*(ctx: var LEA128Ctx, key: array[16, uint8]): void =
    leaInitC(ctx, key.toSliceArray(0, 15))
  template lea128Init*(ctx: var LEA128Ctx, key: openArray[uint8]): void =
    leaInitC(ctx, key.toSliceArray(0, 15))
  template lea128Init*(ctx: var LEA128Ctx, key: slicearray[16, uint8]): void =
    leaInitC(ctx, key)
  template lea128Init*(ctx: ptr LEA128Ctx, key: ptr array[16, uint8]): void =
    leaInitC(ctx[], key.toSliceArray(0, 15))

  template lea128Encrypt*(ctx: LEA128Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    leaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template lea128Encrypt*(ctx: LEA128Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    leaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template lea128Encrypt*(ctx: LEA128Ctx, input, output: slicearray[16, uint8]): void =
    leaEncryptC(ctx, input, output)
  template lea128Encrypt*(ctx: LEA128Ctx, input, output: ptr array[16, uint8]): void =
    leaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template lea128Decrypt*(ctx: LEA128Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    leaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template lea128Decrypt*(ctx: LEA128Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    leaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template lea128Decrypt*(ctx: LEA128Ctx, input, output: slicearray[16, uint8]): void =
    leaDecryptC(ctx, input, output)
  template lea128Decrypt*(ctx: LEA128Ctx, input, output: ptr array[16, uint8]): void =
    leaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template lea192Init*(ctx: var LEA192Ctx, key: array[24, uint8]): void =
    leaInitC(ctx, key.toSliceArray(0, 23))
  template lea192Init*(ctx: var LEA192Ctx, key: openArray[uint8]): void =
    leaInitC(ctx, key.toSliceArray(0, 23))
  template lea192Init*(ctx: var LEA192Ctx, key: slicearray[24, uint8]): void =
    leaInitC(ctx, key)
  template lea192Init*(ctx: ptr LEA192Ctx, key: ptr array[24, uint8]): void =
    leaInitC(ctx[], key.toSliceArray(0, 23))

  template lea192Encrypt*(ctx: LEA192Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    leaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template lea192Encrypt*(ctx: LEA192Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    leaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template lea192Encrypt*(ctx: LEA192Ctx, input, output: slicearray[16, uint8]): void =
    leaEncryptC(ctx, input, output)
  template lea192Encrypt*(ctx: LEA192Ctx, input, output: ptr array[16, uint8]): void =
    leaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template lea192Decrypt*(ctx: LEA192Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    leaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template lea192Decrypt*(ctx: LEA192Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    leaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template lea192Decrypt*(ctx: LEA192Ctx, input, output: slicearray[16, uint8]): void =
    leaDecryptC(ctx, input, output)
  template lea192Decrypt*(ctx: LEA192Ctx, input, output: ptr array[16, uint8]): void =
    leaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template lea256Init*(ctx: var LEA256Ctx, key: array[32, uint8]): void =
    leaInitC(ctx, key.toSliceArray(0, 31))
  template lea256Init*(ctx: var LEA256Ctx, key: openArray[uint8]): void =
    leaInitC(ctx, key.toSliceArray(0, 31))
  template lea256Init*(ctx: var LEA256Ctx, key: slicearray[32, uint8]): void =
    leaInitC(ctx, key)
  template lea256Init*(ctx: ptr LEA256Ctx, key: ptr array[32, uint8]): void =
    leaInitC(ctx[], key.toSliceArray(0, 31))

  template lea256Encrypt*(ctx: LEA256Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    leaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template lea256Encrypt*(ctx: LEA256Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    leaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template lea256Encrypt*(ctx: LEA256Ctx, input, output: slicearray[16, uint8]): void =
    leaEncryptC(ctx, input, output)
  template lea256Encrypt*(ctx: LEA256Ctx, input, output: ptr array[16, uint8]): void =
    leaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template lea256Decrypt*(ctx: LEA256Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    leaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template lea256Decrypt*(ctx: LEA256Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    leaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template lea256Decrypt*(ctx: LEA256Ctx, input, output: slicearray[16, uint8]): void =
    leaDecryptC(ctx, input, output)
  template lea256Decrypt*(ctx: LEA256Ctx, input, output: ptr array[16, uint8]): void =
    leaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
else:
  proc lea128Init*(ctx: var LEA128Ctx, key: array[16, uint8]): void =
    leaInitC(ctx, key.toSliceArray(0, 15))
  proc lea128Init*(ctx: var LEA128Ctx, key: openArray[uint8]): void =
    leaInitC(ctx, key.toSliceArray(0, 15))
  proc lea128Init*(ctx: var LEA128Ctx, key: slicearray[16, uint8]): void =
    leaInitC(ctx, key)
  proc lea128Init*(ctx: ptr LEA128Ctx, key: ptr array[16, uint8]): void =
    leaInitC(ctx[], key.toSliceArray(0, 15))

  proc lea128Encrypt*(ctx: LEA128Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    leaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc lea128Encrypt*(ctx: LEA128Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    leaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc lea128Encrypt*(ctx: LEA128Ctx, input, output: slicearray[16, uint8]): void =
    leaEncryptC(ctx, input, output)
  proc lea128Encrypt*(ctx: LEA128Ctx, input, output: ptr array[16, uint8]): void =
    leaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc lea128Decrypt*(ctx: LEA128Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    leaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc lea128Decrypt*(ctx: LEA128Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    leaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc lea128Decrypt*(ctx: LEA128Ctx, input, output: slicearray[16, uint8]): void =
    leaDecryptC(ctx, input, output)
  proc lea128Decrypt*(ctx: LEA128Ctx, input, output: ptr array[16, uint8]): void =
    leaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc lea192Init*(ctx: var LEA192Ctx, key: array[24, uint8]): void =
    leaInitC(ctx, key.toSliceArray(0, 23))
  proc lea192Init*(ctx: var LEA192Ctx, key: openArray[uint8]): void =
    leaInitC(ctx, key.toSliceArray(0, 23))
  proc lea192Init*(ctx: var LEA192Ctx, key: slicearray[24, uint8]): void =
    leaInitC(ctx, key)
  proc lea192Init*(ctx: ptr LEA192Ctx, key: ptr array[24, uint8]): void =
    leaInitC(ctx[], key.toSliceArray(0, 23))

  proc lea192Encrypt*(ctx: LEA192Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    leaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc lea192Encrypt*(ctx: LEA192Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    leaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc lea192Encrypt*(ctx: LEA192Ctx, input, output: slicearray[16, uint8]): void =
    leaEncryptC(ctx, input, output)
  proc lea192Encrypt*(ctx: LEA192Ctx, input, output: ptr array[16, uint8]): void =
    leaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc lea192Decrypt*(ctx: LEA192Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    leaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc lea192Decrypt*(ctx: LEA192Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    leaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc lea192Decrypt*(ctx: LEA192Ctx, input, output: slicearray[16, uint8]): void =
    leaDecryptC(ctx, input, output)
  proc lea192Decrypt*(ctx: LEA192Ctx, input, output: ptr array[16, uint8]): void =
    leaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc lea256Init*(ctx: var LEA256Ctx, key: array[32, uint8]): void =
    leaInitC(ctx, key.toSliceArray(0, 31))
  proc lea256Init*(ctx: var LEA256Ctx, key: openArray[uint8]): void =
    leaInitC(ctx, key.toSliceArray(0, 31))
  proc lea256Init*(ctx: var LEA256Ctx, key: slicearray[32, uint8]): void =
    leaInitC(ctx, key)
  proc lea256Init*(ctx: ptr LEA256Ctx, key: ptr array[32, uint8]): void =
    leaInitC(ctx[], key.toSliceArray(0, 31))

  proc lea256Encrypt*(ctx: LEA256Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    leaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc lea256Encrypt*(ctx: LEA256Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    leaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc lea256Encrypt*(ctx: LEA256Ctx, input, output: slicearray[16, uint8]): void =
    leaEncryptC(ctx, input, output)
  proc lea256Encrypt*(ctx: LEA256Ctx, input, output: ptr array[16, uint8]): void =
    leaEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc lea256Decrypt*(ctx: LEA256Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    leaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc lea256Decrypt*(ctx: LEA256Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    leaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc lea256Decrypt*(ctx: LEA256Ctx, input, output: slicearray[16, uint8]): void =
    leaDecryptC(ctx, input, output)
  proc lea256Decrypt*(ctx: LEA256Ctx, input, output: ptr array[16, uint8]): void =
    leaDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
