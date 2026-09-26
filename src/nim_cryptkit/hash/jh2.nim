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
  JH2_224IV: array[16, uint64] = [
    0x2dfedd62f99a98ac'u64, 0xae7cacd619d634e7'u64,
    0xa4831005bc301216'u64, 0xb86038c6c9661494'u64,
    0x66d9899f2580706f'u64, 0xce9ea31b1d9b1adc'u64,
    0x11e8325f7b366e10'u64, 0xf994857f02fa06c1'u64,
    0x1b4f1b5cd8c840b3'u64, 0x97f6a17f6e738099'u64,
    0xdcdf93a5adeaa3d3'u64, 0xa431e8dec9539a68'u64,
    0x22b4a98aec86a1e4'u64, 0xd574ac959ce56cf0'u64,
    0x15960deab5ab2bbf'u64, 0x9611dcf0dd64ea6e'u64
  ]

  JH2_256IV: array[16, uint64] = [
    0xeb98a3412c20d3eb'u64, 0x92cdbe7b9cb245c1'u64,
    0x1c93519160d4c7fa'u64, 0x260082d67e508a03'u64,
    0xa4239e267726b945'u64, 0xe0fb1a48d41a9477'u64,
    0xcdb5ab26026b177a'u64, 0x56f024420fff2fa8'u64,
    0x71a396897f2e4d75'u64, 0x1d144908f77de262'u64,
    0x277695f776248f94'u64, 0x87d5b6574780296c'u64,
    0x5c5e272dac8e0d6c'u64, 0x518450c657057a0f'u64,
    0x7be4d367702412ea'u64, 0x89e3ab13d31cd769'u64
  ]

  JH2_384IV: array[16, uint64] = [
    0x481e3bc6d813398a'u64, 0x6d3b5e894ade879b'u64,
    0x63faea68d480ad2e'u64, 0x332ccb21480f8267'u64,
    0x98aec84d9082b928'u64, 0xd455ea3041114249'u64,
    0x36f555b2924847ec'u64, 0xc7250a93baf43ce1'u64,
    0x569b7f8a27db454c'u64, 0x9efcbd496397af0e'u64,
    0x589fc27d26aa80cd'u64, 0x80c08b8c9deb2eda'u64,
    0x8a7981e8f8d5373a'u64, 0xf43967adddd17a71'u64,
    0xa9b4d3bda475d394'u64, 0x976c3fba9842737f'u64
  ]

  JH2_512IV: array[16, uint64] = [
    0x6fd14b963e00aa17'u64, 0x636a2e057a15d543'u64,
    0x8a225e8d0c97ef0b'u64, 0xe9341259f2b3c361'u64,
    0x891da0c1536f801e'u64, 0x2aa9056bea2b6d80'u64,
    0x588eccdb2075baa6'u64, 0xa90f3a76baf83bf7'u64,
    0x0169e60541e34a69'u64, 0x46b58a8e2e6fe65a'u64,
    0x1047a7d0c1843c24'u64, 0x3b6e71b12d5ac199'u64,
    0xcf57f6ec9db1f856'u64, 0xa706887c5716b156'u64,
    0xe3c2fcdfe68517fb'u64, 0x545a4678cc8cdd4b'u64
  ]

  JH2C: array[168, uint64] = [
    0x72d5dea2df15f867'u64, 0x7b84150ab7231557'u64,
    0x81abd6904d5a87f6'u64, 0x4e9f4fc5c3d12b40'u64,
    0xea983ae05c45fa9c'u64, 0x03c5d29966b2999a'u64,
    0x660296b4f2bb538a'u64, 0xb556141a88dba231'u64,
    0x03a35a5c9a190edb'u64, 0x403fb20a87c14410'u64,
    0x1c051980849e951d'u64, 0x6f33ebad5ee7cddc'u64,
    0x10ba139202bf6b41'u64, 0xdc786515f7bb27d0'u64,
    0x0a2c813937aa7850'u64, 0x3f1abfd2410091d3'u64,
    0x422d5a0df6cc7e90'u64, 0xdd629f9c92c097ce'u64,
    0x185ca70bc72b44ac'u64, 0xd1df65d663c6fc23'u64,
    0x976e6c039ee0b81a'u64, 0x2105457e446ceca8'u64,
    0xeef103bb5d8e61fa'u64, 0xfd9697b294838197'u64,
    0x4a8e8537db03302f'u64, 0x2a678d2dfb9f6a95'u64,
    0x8afe7381f8b8696c'u64, 0x8ac77246c07f4214'u64,
    0xc5f4158fbdc75ec4'u64, 0x75446fa78f11bb80'u64,
    0x52de75b7aee488bc'u64, 0x82b8001e98a6a3f4'u64,
    0x8ef48f33a9a36315'u64, 0xaa5f5624d5b7f989'u64,
    0xb6f1ed207c5ae0fd'u64, 0x36cae95a06422c36'u64,
    0xce2935434efe983d'u64, 0x533af974739a4ba7'u64,
    0xd0f51f596f4e8186'u64, 0x0e9dad81afd85a9f'u64,
    0xa7050667ee34626a'u64, 0x8b0b28be6eb91727'u64,
    0x47740726c680103f'u64, 0xe0a07e6fc67e487b'u64,
    0x0d550aa54af8a4c0'u64, 0x91e3e79f978ef19e'u64,
    0x8676728150608dd4'u64, 0x7e9e5a41f3e5b062'u64,
    0xfc9f1fec4054207a'u64, 0xe3e41a00cef4c984'u64,
    0x4fd794f59dfa95d8'u64, 0x552e7e1124c354a5'u64,
    0x5bdf7228bdfe6e28'u64, 0x78f57fe20fa5c4b2'u64,
    0x05897cefee49d32e'u64, 0x447e9385eb28597f'u64,
    0x705f6937b324314a'u64, 0x5e8628f11dd6e465'u64,
    0xc71b770451b920e7'u64, 0x74fe43e823d4878a'u64,
    0x7d29e8a3927694f2'u64, 0xddcb7a099b30d9c1'u64,
    0x1d1b30fb5bdc1be0'u64, 0xda24494ff29c82bf'u64,
    0xa4e7ba31b470bfff'u64, 0x0d324405def8bc48'u64,
    0x3baefc3253bbd339'u64, 0x459fc3c1e0298ba0'u64,
    0xe5c905fdf7ae090f'u64, 0x947034124290f134'u64,
    0xa271b701e344ed95'u64, 0xe93b8e364f2f984a'u64,
    0x88401d63a06cf615'u64, 0x47c1444b8752afff'u64,
    0x7ebb4af1e20ac630'u64, 0x4670b6c5cc6e8ce6'u64,
    0xa4d5a456bd4fca00'u64, 0xda9d844bc83e18ae'u64,
    0x7357ce453064d1ad'u64, 0xe8a6ce68145c2567'u64,
    0xa3da8cf2cb0ee116'u64, 0x33e906589a94999a'u64,
    0x1f60b220c26f847b'u64, 0xd1ceac7fa0d18518'u64,
    0x32595ba18ddd19d3'u64, 0x509a1cc0aaa5b446'u64,
    0x9f3d6367e4046bba'u64, 0xf6ca19ab0b56ee7e'u64,
    0x1fb179eaa9282174'u64, 0xe9bdf7353b3651ee'u64,
    0x1d57ac5a7550d376'u64, 0x3a46c2fea37d7001'u64,
    0xf735c1af98a4d842'u64, 0x78edec209e6b6779'u64,
    0x41836315ea3adba8'u64, 0xfac33b4d32832c83'u64,
    0xa7403b1f1c2747f3'u64, 0x5940f034b72d769a'u64,
    0xe73e4e6cd2214ffd'u64, 0xb8fd8d39dc5759ef'u64,
    0x8d9b0c492b49ebda'u64, 0x5ba2d74968f3700d'u64,
    0x7d3baed07a8d5584'u64, 0xf5a5e9f0e4f88e65'u64,
    0xa0b8a2f436103b53'u64, 0x0ca8079e753eec5a'u64,
    0x9168949256e8884f'u64, 0x5bb05c55f8babc4c'u64,
    0xe3bb3b99f387947b'u64, 0x75daf4d6726b1c5d'u64,
    0x64aeac28dc34b36d'u64, 0x6c34a550b828db71'u64,
    0xf861e2f2108d512a'u64, 0xe3db643359dd75fc'u64,
    0x1cacbcf143ce3fa2'u64, 0x67bbd13c02e843b0'u64,
    0x330a5bca8829a175'u64, 0x7f34194db416535c'u64,
    0x923b94c30e794d1e'u64, 0x797475d7b6eeaf3f'u64,
    0xeaa8d4f7be1a3921'u64, 0x5cf47e094c232751'u64,
    0x26a32453ba323cd2'u64, 0x44a3174a6da6d5ad'u64,
    0xb51d3ea6aff2c908'u64, 0x83593d98916b3c56'u64,
    0x4cf87ca17286604d'u64, 0x46e23ecc086ec7f6'u64,
    0x2f9833b3b1bc765e'u64, 0x2bd666a5efc4e62a'u64,
    0x06f4b6e8bec1d436'u64, 0x74ee8215bcef2163'u64,
    0xfdc14e0df453c969'u64, 0xa77d5ac406585826'u64,
    0x7ec1141606e0fa16'u64, 0x7e90af3d28639d3f'u64,
    0xd2c9f2e3009bd20c'u64, 0x5faace30b7d40c30'u64,
    0x742a5116f2e03298'u64, 0x0deb30d8e3cef89a'u64,
    0x4bc59e7bb5f17992'u64, 0xff51e66e048668d3'u64,
    0x9b234d57e6966731'u64, 0xcce6a6f3170a7505'u64,
    0xb17681d913326cce'u64, 0x3c175284f805a262'u64,
    0xf42bcbb378471547'u64, 0xff46548223936a48'u64,
    0x38df58074e5e6565'u64, 0xf2fc7c89fc86508e'u64,
    0x31702e44d00bca86'u64, 0xf04009a23078474e'u64,
    0x65a0ee39d1f73883'u64, 0xf75ee937e42c3abd'u64,
    0x2197b2260113f86f'u64, 0xa344edd1ef9fdee7'u64,
    0x8ba0df15762592d9'u64, 0x3c85f7f612dc42be'u64,
    0xd8a7ec7cab27b07e'u64, 0x538d7ddaaa3ea8de'u64,
    0xaa25ce93bd0269d8'u64, 0x5af643fd1a7308f9'u64,
    0xc05fefda174a19a5'u64, 0x974d66334cfd216a'u64,
    0x35b49831db411570'u64, 0xea1e0fbbedcd549b'u64,
    0x9ad063a151974072'u64, 0xf6759dbf91476fe2'u64
  ]

type
  JH2Ctx*[hashSize: static int, blockSize: static int] = object
    state*: array[16, uint64]
    buffer*: array[blockSize, uint8]
    index*: int
    length*: uint64

  JH2_224Ctx* = JH2Ctx[28, 64]
  JH2_256Ctx* = JH2Ctx[32, 64]
  JH2_384Ctx* = JH2Ctx[48, 64]
  JH2_512Ctx* = JH2Ctx[64, 64]

template jh2S(state: var array[16, uint64], roundIndex: int): void =
  for col in static(0 ..< 4):
    let c = JH2C[(roundIndex shl 2) + col]
    var x0 = state[col]
    var x1 = state[col + 4]
    var x2 = state[col + 8]
    var x3 = state[col + 12]
    x3 = not x3
    x0 = x0 xor (c and (not x2))
    let tmp = c xor (x0 and x1)
    x0 = x0 xor (x2 and x3)
    x3 = x3 xor ((not x1) and x2)
    x1 = x1 xor (x0 and x2)
    x2 = x2 xor (x0 and (not x3))
    x0 = x0 xor (x1 or x3)
    x3 = x3 xor (x1 and x2)
    x1 = x1 xor (tmp and x0)
    x2 = x2 xor tmp
    state[col] = x0
    state[col + 4] = x1
    state[col + 8] = x2
    state[col + 12] = x3

template round(state: var array[16, uint64], a0, a1, a2, a3, a4, a5, a6, a7: static int): void =
  var x0 = state[a0]
  var x1 = state[a1]
  var x2 = state[a2]
  var x3 = state[a3]
  var x4 = state[a4]
  var x5 = state[a5]
  var x6 = state[a6]
  var x7 = state[a7]
  x4 = x4 xor x1
  x5 = x5 xor x2
  x6 = x6 xor x3 xor x0
  x7 = x7 xor x0
  x0 = x0 xor x5
  x1 = x1 xor x6
  x2 = x2 xor x7 xor x4
  x3 = x3 xor x4
  state[a0] = x0
  state[a1] = x1
  state[a2] = x2
  state[a3] = x3
  state[a4] = x4
  state[a5] = x5
  state[a6] = x6
  state[a7] = x7

template jh2L(state: var array[16, uint64]): void =
  round(state, 0, 4, 8, 12, 2, 6, 10, 14)
  round(state, 1, 5, 9, 13, 3, 7, 11, 15)

template jh2Wgen(state: var array[16, uint64], mask: uint64, shift: int): void =
  for idx in [2, 3, 6, 7, 10, 11, 14, 15]:
    state[idx] = ((state[idx] and mask) shl shift) or ((state[idx] shr shift) and mask)

proc jh2W6(state: var array[16, uint64]) =
  for a in [2, 6, 10, 14]:
    swap(state[a], state[a + 1])

template jh2Transform(state: var array[16, uint64], chunk: slicearray[64,uint8]): void =
  var message: array[8, uint64]
  decodeBE(chunk, message.toSliceArray(0, 7))

  state[0] = state[0] xor message[0]
  state[1] = state[1] xor message[1]
  state[2] = state[2] xor message[2]
  state[3] = state[3] xor message[3]
  state[4] = state[4] xor message[4]
  state[5] = state[5] xor message[5]
  state[6] = state[6] xor message[6]
  state[7] = state[7] xor message[7]

  for i in static(0 ..< 6):
    jh2S(state, i * 7 + 0)
    jh2L(state)
    jh2Wgen(state, 0x5555555555555555'u64, 1)
    jh2S(state, i * 7 + 1)
    jh2L(state)
    jh2Wgen(state, 0x3333333333333333'u64, 2)
    jh2S(state, i * 7 + 2)
    jh2L(state)
    jh2Wgen(state, 0x0f0f0f0f0f0f0f0f'u64, 4)
    jh2S(state, i * 7 + 3)
    jh2L(state)
    jh2Wgen(state, 0x00ff00ff00ff00ff'u64, 8)
    jh2S(state, i * 7 + 4)
    jh2L(state)
    jh2Wgen(state, 0x0000ffff0000ffff'u64, 16)
    jh2S(state, i * 7 + 5)
    jh2L(state)
    jh2Wgen(state, 0x00000000ffffffff'u64, 32)
    jh2S(state, i * 7 + 6)
    jh2L(state)
    jh2W6(state)

  state[8] = state[8] xor message[0]
  state[9] = state[9] xor message[1]
  state[10] = state[10] xor message[2]
  state[11] = state[11] xor message[3]
  state[12] = state[12] xor message[4]
  state[13] = state[13] xor message[5]
  state[14] = state[14] xor message[6]
  state[15] = state[15] xor message[7]

template jh2InitC[K, B: static int](ctx: var JH2Ctx[K, B]): void =
  when K == 28:
    ctx.state = JH2_224IV
  elif K == 32:
    ctx.state = JH2_256IV
  elif K == 48:
    ctx.state = JH2_384IV
  elif K == 64:
    ctx.state = JH2_512IV
  ctx.index = 0
  ctx.length = 0'u64
  zeroMem(addr ctx.buffer, B)

template jh2InputC[K, B: static int](ctx: var JH2Ctx[K, B], input: openArray[uint8]): void =
  let inputLen: int = input.len
  var check: bool = true

  if inputLen <= 0: check = false

  if check:
    var index: int = ctx.index
    ctx.length += inputLen.uint64

    let left: int = B - index
    var position: int = 0

    if inputLen >= left:
      if left > 0:
        copyMem(addr ctx.buffer[index], addr input[0], left)
      jh2Transform(ctx.state, ctx.buffer.toSliceArray(0, B - 1))
      position = left
      index = 0

      while position + B <= inputLen:
        jh2Transform(ctx.state, input.toSliceArray(position, position + B - 1, B))
        position += B

    let remain: int = inputLen - position
    if remain > 0:
      copyMem(addr ctx.buffer[index], addr input[position], remain)
      index += remain

    ctx.index = index

template jh2FinalC[K, B: static int](ctx: var Jh2Ctx[K, B]): array[K, uint8] =
  var output: array[K, uint8]

  var index: int = ctx.index

  ctx.buffer[index] = 0x80'u8
  index.inc

  let padLen: int = if index == 1: 56 - index else: 64 - index

  if index == 1:
    zeroMem(addr ctx.buffer[index], padLen)
  else:
    if padLen > 0:
      zeroMem(addr ctx.buffer[index], padLen)
    jh2Transform(ctx.state, ctx.buffer.toSliceArray(0, B - 1))
    zeroMem(addr ctx.buffer[0], 56)

  ctx.length = ctx.length shl 3

  toBytesBE(ctx.length, ctx.buffer.toSliceArray(56, 63))

  jh2Transform(ctx.state, ctx.buffer.toSliceArray(0, B - 1))

  var temp: array[64, uint8]
  encodeBE(ctx.state.toSliceArray(8, 15), temp.toSliceArray(0, 63))

  const starts: int = 64 - K
  copyMem(addr output[0], addr temp[starts], K)

  output

# export wrappers
when defined(templateOpt):
  template jh2_224Init*(ctx: var JH2_224Ctx): void = jh2InitC(ctx)
  template jh2_224Input*(ctx: var JH2_224Ctx, input: openArray[uint8]): void = jh2InputC(ctx, input)
  template jh2_224Final*(ctx: var JH2_224Ctx): array[28, uint8] = jh2FinalC(ctx)

  template jh2_256Init*(ctx: var JH2_256Ctx): void = jh2InitC(ctx)
  template jh2_256Input*(ctx: var JH2_256Ctx, input: openArray[uint8]): void = jh2InputC(ctx, input)
  template jh2_256Final*(ctx: var JH2_256Ctx): array[32, uint8] = jh2FinalC(ctx)

  template jh2_384Init*(ctx: var JH2_384Ctx): void = jh2InitC(ctx)
  template jh2_384Input*(ctx: var JH2_384Ctx, input: openArray[uint8]): void = jh2InputC(ctx, input)
  template jh2_384Final*(ctx: var JH2_384Ctx): array[48, uint8] = jh2FinalC(ctx)

  template jh2_512Init*(ctx: var JH2_512Ctx): void = jh2InitC(ctx)
  template jh2_512Input*(ctx: var JH2_512Ctx, input: openArray[uint8]): void = jh2InputC(ctx, input)
  template jh2_512Final*(ctx: var JH2_512Ctx): array[64, uint8] = jh2FinalC(ctx)

  when Native:
    template jh2_224Init*(ctx: ptr JH2_224Ctx): void = jh2InitC(ctx[])
    template jh2_224Input*(ctx: ptr JH2_224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = jh2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template jh2_224Final*(ctx: ptr JH2_224Ctx, output: ptr array[28, uint8]): void = output[] = jh2FinalC(ctx[])

    template jh2_256Init*(ctx: ptr JH2_256Ctx): void = jh2InitC(ctx[])
    template jh2_256Input*(ctx: ptr JH2_256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = jh2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template jh2_256Final*(ctx: ptr JH2_256Ctx, output: ptr array[32, uint8]): void = output[] = jh2FinalC(ctx[])

    template jh2_384Init*(ctx: ptr JH2_384Ctx): void = jh2InitC(ctx[])
    template jh2_384Input*(ctx: ptr JH2_384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = jh2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template jh2_384Final*(ctx: ptr JH2_384Ctx, output: ptr array[48, uint8]): void = output[] = jh2FinalC(ctx[])

    template jh2_512Init*(ctx: ptr JH2_512Ctx): void = jh2InitC(ctx[])
    template jh2_512Input*(ctx: ptr JH2_512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = jh2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template jh2_512Final*(ctx: ptr JH2_512Ctx, output: ptr array[64, uint8]): void = output[] = jh2FinalC(ctx[])

else:
  when Native:
    proc jh2_224Init*(ctx: var JH2_224Ctx): void = jh2InitC(ctx)
    proc jh2_224Input*(ctx: var JH2_224Ctx, input: openArray[uint8]): void = jh2InputC(ctx, input)
    proc jh2_224Final*(ctx: var JH2_224Ctx): array[28, uint8] = jh2FinalC(ctx)

    proc jh2_256Init*(ctx: var JH2_256Ctx): void = jh2InitC(ctx)
    proc jh2_256Input*(ctx: var JH2_256Ctx, input: openArray[uint8]): void = jh2InputC(ctx, input)
    proc jh2_256Final*(ctx: var JH2_256Ctx): array[32, uint8] = jh2FinalC(ctx)

    proc jh2_384Init*(ctx: var JH2_384Ctx): void = jh2InitC(ctx)
    proc jh2_384Input*(ctx: var JH2_384Ctx, input: openArray[uint8]): void = jh2InputC(ctx, input)
    proc jh2_384Final*(ctx: var JH2_384Ctx): array[48, uint8] = jh2FinalC(ctx)

    proc jh2_512Init*(ctx: var JH2_512Ctx): void = jh2InitC(ctx)
    proc jh2_512Input*(ctx: var JH2_512Ctx, input: openArray[uint8]): void = jh2InputC(ctx, input)
    proc jh2_512Final*(ctx: var JH2_512Ctx): array[64, uint8] = jh2FinalC(ctx)

  when defined(c) or defined(objc):
    proc jh2_224Init*(ctx: ptr JH2_224Ctx): void {.exportc: "jh2_224Init".} = jh2InitC(ctx[])
    proc jh2_224Input*(ctx: ptr JH2_224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "jh2_224Input".} = jh2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc jh2_224Final*(ctx: ptr JH2_224Ctx, output: ptr array[28, uint8]): void {.exportc: "jh2_224Final".} = output[] = jh2FinalC(ctx[])

    proc jh2_256Init*(ctx: ptr JH2_256Ctx): void {.exportc: "jh2_256Init".} = jh2InitC(ctx[])
    proc jh2_256Input*(ctx: ptr JH2_256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "jh2_256Input".} = jh2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc jh2_256Final*(ctx: ptr JH2_256Ctx, output: ptr array[32, uint8]): void {.exportc: "jh2_256Final".} = output[] = jh2FinalC(ctx[])

    proc jh2_384Init*(ctx: ptr JH2_384Ctx): void {.exportc: "jh2_384Init".} = jh2InitC(ctx[])
    proc jh2_384Input*(ctx: ptr JH2_384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "jh2_384Input".} = jh2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc jh2_384Final*(ctx: ptr JH2_384Ctx, output: ptr array[48, uint8]): void {.exportc: "jh2_384Final".} = output[] = jh2FinalC(ctx[])

    proc jh2_512Init*(ctx: ptr JH2_512Ctx): void {.exportc: "jh2_512Init".} = jh2InitC(ctx[])
    proc jh2_512Input*(ctx: ptr JH2_512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "jh2_512Input".} = jh2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc jh2_512Final*(ctx: ptr JH2_512Ctx, output: ptr array[64, uint8]): void {.exportc: "jh2_512Final".} = output[] = jh2FinalC(ctx[])

  elif defined(cpp):
    proc jh2_224Init*(ctx: ptr JH2_224Ctx): void {.exportcpp: "jh2_224Init".} = jh2InitC(ctx[])
    proc jh2_224Input*(ctx: ptr JH2_224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "jh2_224Input".} = jh2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc jh2_224Final*(ctx: ptr JH2_224Ctx, output: ptr array[28, uint8]): void {.exportcpp: "jh2_224Final".} = output[] = jh2FinalC(ctx[])

    proc jh2_256Init*(ctx: ptr JH2_256Ctx): void {.exportcpp: "jh2_256Init".} = jh2InitC(ctx[])
    proc jh2_256Input*(ctx: ptr JH2_256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "jh2_256Input".} = jh2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc jh2_256Final*(ctx: ptr JH2_256Ctx, output: ptr array[32, uint8]): void {.exportcpp: "jh2_256Final".} = output[] = jh2FinalC(ctx[])

    proc jh2_384Init*(ctx: ptr JH2_384Ctx): void {.exportcpp: "jh2_384Init".} = jh2InitC(ctx[])
    proc jh2_384Input*(ctx: ptr JH2_384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "jh2_384Input".} = jh2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc jh2_384Final*(ctx: ptr JH2_384Ctx, output: ptr array[48, uint8]): void {.exportcpp: "jh2_384Final".} = output[] = jh2FinalC(ctx[])

    proc jh2_512Init*(ctx: ptr JH2_512Ctx): void {.exportcpp: "jh2_512Init".} = jh2InitC(ctx[])
    proc jh2_512Input*(ctx: ptr JH2_512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "jh2_512Input".} = jh2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc jh2_512Final*(ctx: ptr JH2_512Ctx, output: ptr array[64, uint8]): void {.exportcpp: "jh2_512Final".} = output[] = jh2FinalC(ctx[])
