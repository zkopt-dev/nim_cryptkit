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
  IV224: array[8, array[2, uint64]] = [
     [0xac989af962ddfe2d'u64, 0xe734d619d6ac7cae'u64],
     [0x161230bc051083a4'u64, 0x941466c9c63860b8'u64],
     [0x6f7080259f89d966'u64, 0xdc1a9b1d1ba39ece'u64],
     [0x106e367b5f32e811'u64, 0xc106fa027f8594f9'u64],
     [0xb340c8d85c1b4f1b'u64, 0x9980736e7fa1f697'u64],
     [0xd3a3eaada593dfdc'u64, 0x689a53c9dee831a4'u64],
     [0xe4a186ec8aa9b422'u64, 0xf06ce59c95ac74d5'u64],
     [0xbf2babb5ea0d9615'u64, 0x6eea64ddf0dc1196'u64]
   ]
  IV256: array[8, array[2, uint64]] = [
    [0xebd3202c41a398eb'u64, 0xc145b29c7bbecd92'u64],
    [0xfac7d4609151931c'u64, 0x038a507ed6820026'u64],
    [0x45b92677269e23a4'u64, 0x77941ad4481afbe0'u64],
    [0x7a176b0226abb5cd'u64, 0xa82fff0f4224f056'u64],
    [0x754d2e7f8996a371'u64, 0x62e27df70849141d'u64],
    [0x948f2476f7957627'u64, 0x6c29804757b6d587'u64],
    [0x6c0d8eac2d275e5c'u64, 0x0f7a0557c6508451'u64],
    [0xea12247067d3e47b'u64, 0x69d71cd313abe389'u64]]
  IV384: array[8, array[2, uint64]] = [
    [0x8a3913d8c63b1e48'u64, 0x9b87de4a895e3b6d'u64],
    [0x2ead80d468eafa63'u64, 0x67820f4821cb2c33'u64],
    [0x28b982904dc8ae98'u64, 0x4942114130ea55d4'u64],
    [0xec474892b255f536'u64, 0xe13cf4ba930a25c7'u64],
    [0x4c45db278a7f9b56'u64, 0x0eaf976349bdfc9e'u64],
    [0xcd80aa267dc29f58'u64, 0xda2eeb9d8c8bc080'u64],
    [0x3a37d5f8e881798a'u64, 0x717ad1ddad6739f4'u64],
    [0x94d375a4bdd3b4a9'u64, 0x7f734298ba3f6c97'u64]
  ]
  IV512: array[8, array[2, uint64]] = [
    [0x17aa003e964bd16f'u64, 0x43d5157a052e6a63'u64],
    [0x0bef970c8d5e228a'u64, 0x61c3b3f2591234e9'u64],
    [0x1e806f53c1a01d89'u64, 0x806d2bea6b05a92a'u64],
    [0xa6ba7520dbcc8e58'u64, 0xf73bf8ba763a0fa9'u64],
    [0x694ae34105e66901'u64, 0x5ae66f2e8e8ab546'u64],
    [0x243c84c1d0a74710'u64, 0x99c15a2db1716e3b'u64],
    [0x56f8b19decf657cf'u64, 0x56b116577c8806a7'u64],
    [0xfb1785e6dffcc2e3'u64, 0x4bdd8ccc78465a54'u64]
  ]

  RC: array[42, array[4, uint64]] = [
    [0x67f815dfa2ded572'u64, 0x571523b70a15847b'u64,
     0xf6875a4d90d6ab81'u64, 0x402bd1c3c54f9f4e'u64],
    [0x9cfa455ce03a98ea'u64, 0x9a99b26699d2c503'u64,
     0x8a53bbf2b4960266'u64, 0x31a2db881a1456b5'u64],
    [0xdb0e199a5c5aa303'u64, 0x1044c1870ab23f40'u64,
     0x1d959e848019051c'u64, 0xdccde75eadeb336f'u64],
    [0x416bbf029213ba10'u64, 0xd027bbf7156578dc'u64,
     0x5078aa3739812c0a'u64, 0xd3910041d2bf1a3f'u64],
    [0x907eccf60d5a2d42'u64, 0xce97c0929c9f62dd'u64,
     0xac442bc70ba75c18'u64, 0x23fcc663d665dfd1'u64],
    [0x1ab8e09e036c6e97'u64, 0xa8ec6c447e450521'u64,
     0xfa618e5dbb03f1ee'u64, 0x97818394b29796fd'u64],
    [0x2f3003db37858e4a'u64, 0x956a9ffb2d8d672a'u64,
     0x6c69b8f88173fe8a'u64, 0x14427fc04672c78a'u64],
    [0xc45ec7bd8f15f4c5'u64, 0x80bb118fa76f4475'u64,
     0xbc88e4aeb775de52'u64, 0xf4a3a6981e00b882'u64],
    [0x1563a3a9338ff48e'u64, 0x89f9b7d524565faa'u64,
     0xfde05a7c20edf1b6'u64, 0x362c42065ae9ca36'u64],
    [0x3d98fe4e433529ce'u64, 0xa74b9a7374f93a53'u64,
     0x86814e6f591ff5d0'u64, 0x9f5ad8af81ad9d0e'u64],
    [0x6a6234ee670605a7'u64, 0x2717b96ebe280b8b'u64,
     0x3f1080c626077447'u64, 0x7b487ec66f7ea0e0'u64],
    [0xc0a4f84aa50a550d'u64, 0x9ef18e979fe7e391'u64,
     0xd48d605081727686'u64, 0x62b0e5f3415a9e7e'u64],
    [0x7a205440ec1f9ffc'u64, 0x84c9f4ce001ae4e3'u64,
     0xd895fa9df594d74f'u64, 0xa554c324117e2e55'u64],
    [0x286efebd2872df5b'u64, 0xb2c4a50fe27ff578'u64,
     0x2ed349eeef7c8905'u64, 0x7f5928eb85937e44'u64],
    [0x4a3124b337695f70'u64, 0x65e4d61df128865e'u64,
     0xe720b95104771bc7'u64, 0x8a87d423e843fe74'u64],
    [0xf2947692a3e8297d'u64, 0xc1d9309b097acbdd'u64,
     0xe01bdc5bfb301b1d'u64, 0xbf829cf24f4924da'u64],
    [0xffbf70b431bae7a4'u64, 0x48bcf8de0544320d'u64,
     0x39d3bb5332fcae3b'u64, 0xa08b29e0c1c39f45'u64],
    [0x0f09aef7fd05c9e5'u64, 0x34f1904212347094'u64,
     0x95ed44e301b771a2'u64, 0x4a982f4f368e3be9'u64],
    [0x15f66ca0631d4088'u64, 0xffaf52874b44c147'u64,
     0x30c60ae2f14abb7e'u64, 0xe68c6eccc5b67046'u64],
    [0x00ca4fbd56a4d5a4'u64, 0xae183ec84b849dda'u64,
     0xadd1643045ce5773'u64, 0x67255c1468cea6e8'u64],
    [0x16e10ecbf28cdaa3'u64, 0x9a99949a5806e933'u64,
     0x7b846fc220b2601f'u64, 0x1885d1a07facced1'u64],
    [0xd319dd8da15b5932'u64, 0x46b4a5aac01c9a50'u64,
     0xba6b04e467633d9f'u64, 0x7eee560bab19caf6'u64],
    [0x742128a9ea79b11f'u64, 0xee51363b35f7bde9'u64,
     0x76d350755aac571d'u64, 0x1707da3fec2463a'u64],
    [0x42d8a498afc135f7'u64, 0x79676b9e20eced78'u64,
     0xa8db3aea15638341'u64, 0x832c83324d3bc3fa'u64],
    [0xf347271c1f3b40a7'u64, 0x9a762db734f04059'u64,
     0xfd4f21d26c4e3ee7'u64, 0xef5957dc398dfdb8'u64],
    [0xdaeb492b490c9b8d'u64, 0x0d70f36849d7a25b'u64,
     0x84558d7ad0ae3b7d'u64, 0x658ef8e4f0e9a5f5'u64],
    [0x533b1036f4a2b8a0'u64, 0x5aec3e759e07a80c'u64,
     0x4f88e85692946891'u64, 0x4cbcbaf8555cb05b'u64],
    [0x7b9487f3993bbbe3'u64, 0x5d1c6b72d6f4da75'u64,
     0x6db334dc28acae64'u64, 0x71db28b850a5346c'u64],
    [0x2a518d10f2e261f8'u64, 0xfc75dd593364dbe3'u64,
     0xa23fce43f1bcac1c'u64, 0xb043e8023cd1bb67'u64],
    [0x75a12988ca5b0a33'u64, 0x5c5316b44d19347f'u64,
     0x1e4d790ec3943b92'u64, 0x3fafeeb6d7757479'u64],
    [0x21391abef7d4a8ea'u64, 0x5127234c097ef45c'u64,
     0xd23c32ba5324a326'u64, 0xadd5a66d4a17a344'u64],
    [0x08c9f2afa63e1db5'u64, 0x563c6b91983d5983'u64,
     0x4d608672a17cf84c'u64, 0xf6c76e08cc3ee246'u64],
    [0x5e76bcb1b333982f'u64, 0x2ae6c4efa566d62b'u64,
     0x36d4c1bee8b6f406'u64, 0x6321efbc1582ee74'u64],
    [0x69c953f40d4ec1fd'u64, 0x26585806c45a7da7'u64,
     0x16fae0061614c17e'u64, 0x3f9d63283daf907e'u64],
    [0x0cd29b00e3f2c9d2'u64, 0x300cd4b730ceaa5f'u64,
     0x9832e0f216512a74'u64, 0x9af8cee3d830eb0d'u64],
    [0x9279f1b57b9ec54b'u64, 0xd36886046ee651ff'u64,
     0x316796e6574d239b'u64, 0x05750a17f3a6e6cc'u64],
    [0xce6c3213d98176b1'u64, 0x62a205f88452173c'u64,
     0x47154778b3cb2bf4'u64, 0x486a9323825446ff'u64],
    [0x65655e4e0758df38'u64, 0x8e5086fc897cfcf2'u64,
     0x86ca0bd0442e7031'u64, 0x4e477830a20940f0'u64],
    [0x8338f7d139eea065'u64, 0xbd3a2ce437e95ef7'u64,
     0x6ff8130126b29721'u64, 0xe7de9fefd1ed44a3'u64],
    [0xd992257615dfa08b'u64, 0xbe42dc12f6f7853c'u64,
     0x7eb027ab7ceca7d8'u64, 0xdea83eaada7d8d53'u64],
    [0xd86902bd93ce25aa'u64, 0xf908731afd43f65a'u64,
     0xa5194a17daef5fc0'u64, 0x6a21fd4c33664d97'u64],
    [0x701541db3198b435'u64, 0x9b54cdedbb0f1eea'u64,
     0x72409751a163d09a'u64, 0xe26f4791bf9d75f6'u64]]

type
  JHCtx*[hashSize: static int, blockSize: static int] = object
    buffer*: array[64, uint8]
    index*: int
    length*: uint64
    state*: array[8, array[2, uint64]]

  JH224Ctx* = JHCtx[28, 64]
  JH256Ctx* = JHCtx[32, 64]
  JH384Ctx* = JHCtx[48, 64]
  JH512Ctx* = JHCtx[64, 64]


template jhSwap1(x: var uint64): void =
  x = ((x and 0x5555555555555555'u64) shl 1) or
    ((x and 0xaaaaaaaaaaaaaaaa'u64) shr 1)

template jhSwap2(x: var uint64): void =
  x = ((x and 0x3333333333333333'u64) shl 2) or
    ((x and 0xcccccccccccccccc'u64) shr 2)

template jhSwap4(x: var uint64): void =
  x = ((x and 0x0f0f0f0f0f0f0f0f'u64) shl 4) or
    ((x and 0xf0f0f0f0f0f0f0f0'u64) shr 4)

template jhSwap8(x: var uint64): void =
  x = ((x and 0x00ff00ff00ff00ff'u64) shl 8) or
    ((x and 0xff00ff00ff00ff00'u64) shr 8)

template jhSwap16(x: var uint64): void =
  x = ((x and 0x0000ffff0000ffff'u64) shl 16) or
    ((x and 0xffff0000ffff0000'u64) shr 16)

template jhSwap32(x: var uint64): void =
  x = (x shl 32) or (x shr 32)

template jhSBox(m0, m1, m2, m3, m4, m5, m6, m7: var uint64, cc0, cc1: uint64): void =
  var temp0, temp1: uint64
  m3 = not m3
  m7 = not m7
  m0 = m0 xor ((not m2) and cc0)
  m4 = m4 xor ((not m6) and cc1)
  temp0 = cc0 xor (m0 and m1)
  temp1 = cc1 xor (m4 and m5)
  m0 = m0 xor (m2 and m3)
  m4 = m4 xor (m6 and m7)
  m3 = m3 xor ((not m1) and m2)
  m7 = m7 xor ((not m5) and m6)
  m1 = m1 xor (m0 and m2)
  m5 = m5 xor (m4 and m6)
  m2 = m2 xor (m0 and (not m3))
  m6 = m6 xor (m4 and (not m7))
  m0 = m0 xor (m1 or m3)
  m4 = m4 xor (m5 or m7)
  m3 = m3 xor (m1 and m2)
  m7 = m7 xor (m5 and m6)
  m1 = m1 xor (temp0 and m0)
  m5 = m5 xor (temp1 and m4)
  m2 = m2 xor temp0
  m6 = m6 xor temp1

template jhL(m0, m1, m2, m3, m4, m5, m6, m7: var uint64): void =
  m4 = m4 xor m1
  m5 = m5 xor m2
  m6 = m6 xor m0 xor m3
  m7 = m7 xor m0
  m0 = m0 xor m5
  m1 = m1 xor m6
  m2 = m2 xor m4 xor m7
  m3 = m3 xor m4

template jhRound(state: var array[8, array[2, uint64]], roundIndex: int, lane: int): void =
  jhSBox(state[0][lane], state[2][lane], state[4][lane],
         state[6][lane], state[1][lane], state[3][lane],
         state[5][lane], state[7][lane], RC[roundIndex][lane], RC[roundIndex][lane + 2])
  jhL(state[0][lane], state[2][lane], state[4][lane],
      state[6][lane], state[1][lane], state[3][lane],
      state[5][lane], state[7][lane])

template jhE8(state: var array[8, array[2, uint64]]): void =
  for i in static(0 ..< 6):
    for lane in static(0 ..< 2):
      jhRound(state, i * 7 + 0, lane)
      jhSwap1(state[1][lane])
      jhSwap1(state[3][lane])
      jhSwap1(state[5][lane])
      jhSwap1(state[7][lane])

    for lane in static(0 ..< 2):
      jhRound(state, i * 7 + 1, lane)
      jhSwap2(state[1][lane])
      jhSwap2(state[3][lane])
      jhSwap2(state[5][lane])
      jhSwap2(state[7][lane])

    for lane in static(0 ..< 2):
      jhRound(state, i * 7 + 2, lane)
      jhSwap4(state[1][lane])
      jhSwap4(state[3][lane])
      jhSwap4(state[5][lane])
      jhSwap4(state[7][lane])

    for lane in static(0 ..< 2):
      jhRound(state, i * 7 + 3, lane)
      jhSwap8(state[1][lane])
      jhSwap8(state[3][lane])
      jhSwap8(state[5][lane])
      jhSwap8(state[7][lane])

    for lane in static(0 ..< 2):
      jhRound(state, i * 7 + 4, lane)
      jhSwap16(state[1][lane])
      jhSwap16(state[3][lane])
      jhSwap16(state[5][lane])
      jhSwap16(state[7][lane])

    for lane in static(0 ..< 2):
      jhRound(state, i * 7 + 5, lane)
      jhSwap32(state[1][lane])
      jhSwap32(state[3][lane])
      jhSwap32(state[5][lane])
      jhSwap32(state[7][lane])

    for lane in static(0 ..< 2):
      jhRound(state, i * 7 + 6, lane)

    for i in countup(1, 7, 2):
      swap(state[i][0], state[i][1])

template jhTransform(state: var array[8, array[2, uint64]], chunk: slicearray[64, uint8]): void =
  for i in static(0 ..< 8):
    state[i shr 1][i and 1] = state[i shr 1][i and 1] xor fromBytesLE[uint64, 8](chunk.toSliceArray(i * 8, i * 8 + 7, 8))
  jhE8(state)
  for i in static(0 ..< 8):
    state[(8 + i) shr 1][(8 + i) and 1] = state[(8 + i) shr 1][(8 + i) and 1] xor fromBytesLE[uint64, 8](chunk.toSliceArray(i * 8, i * 8 + 7, 8))

template jhInitC[K, B: static int](ctx: var JhCtx[K, B]): void =
  ctx.buffer = default(array[64, uint8])
  ctx.index = 0
  ctx.length = 0'u64
  when K == 28:
    ctx.state = IV224
  elif K == 32:
    ctx.state = IV256
  elif K == 48:
    ctx.state = IV384
  elif K == 64:
    ctx.state = IV512

template jhInputC[K, B: static int](ctx: var JhCtx[K, B], input: openArray[uint8]) =
  let inputLen: int = input.len
  var check: bool = true

  if inputLen <= 0: check = false

  if check:
    var index: int = ctx.index
    ctx.length += inputLen.uint64

    let left: int = 64 - index
    var position: int = 0

    if inputLen >= left:
      if left > 0:
        copyMem(addr ctx.buffer[index], addr input[0], left)
      jhTransform(ctx.state, ctx.buffer.toSliceArray(0, 63))
      position = left
      index = 0

      while position + 64 <= inputLen:
        jhTransform(ctx.state, input.toSliceArray(position, position + 63, 64))
        position += 64

    let remain: int = inputLen - position
    if remain > 0:
      copyMem(addr ctx.buffer[index], addr input[position], remain)
      index += remain

    ctx.index = index

template jhFinalC[K, B: static int](ctx: var JhCtx[K, B]): array[K, uint8] =
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
    jhTransform(ctx.state, ctx.buffer.toSliceArray(0, 63))
    zeroMem(addr ctx.buffer[0], 56)

  let bitLength: uint64 = ctx.length shl 3
  toBytesBE(bitLength, ctx.buffer.toSliceArray(56, 63))

  jhTransform(ctx.state, ctx.buffer.toSliceArray(0, 63))

  var temp: array[64, uint8]
  encodeLE(ctx.state[4].toSliceArray(0, 1), temp.toSliceArray(0, 15))
  encodeLE(ctx.state[5].toSliceArray(0, 1), temp.toSliceArray(16, 31))
  encodeLE(ctx.state[6].toSliceArray(0, 1), temp.toSliceArray(32, 47))
  encodeLE(ctx.state[7].toSliceArray(0, 1), temp.toSliceArray(48, 63))

  const starts: int = 64 - K
  copyMem(addr output, addr temp[starts], K)

  output

# export wrappers
when defined(templateOpt):
  template jh224Init*(ctx: var JH224Ctx): void = jhInitC(ctx)
  template jh224Input*(ctx: var JH224Ctx, input: openArray[uint8]): void = jhInputC(ctx, input)
  template jh224Final*(ctx: var JH224Ctx): array[28, uint8] = jhFinalC(ctx)

  template jh256Init*(ctx: var JH256Ctx): void = jhInitC(ctx)
  template jh256Input*(ctx: var JH256Ctx, input: openArray[uint8]): void = jhInputC(ctx, input)
  template jh256Final*(ctx: var JH256Ctx): array[32, uint8] = jhFinalC(ctx)

  template jh384Init*(ctx: var JH384Ctx): void = jhInitC(ctx)
  template jh384Input*(ctx: var JH384Ctx, input: openArray[uint8]): void = jhInputC(ctx, input)
  template jh384Final*(ctx: var JH384Ctx): array[48, uint8] = jhFinalC(ctx)

  template jh512Init*(ctx: var JH512Ctx): void = jhInitC(ctx)
  template jh512Input*(ctx: var JH512Ctx, input: openArray[uint8]): void = jhInputC(ctx, input)
  template jh512Final*(ctx: var JH512Ctx): array[64, uint8] = jhFinalC(ctx)

  when Native:
    template jh224Init*(ctx: ptr JH224Ctx): void = jhInitC(ctx[])
    template jh224Input*(ctx: ptr JH224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = jhInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template jh224Final*(ctx: ptr JH224Ctx, output: ptr array[28, uint8]): void = output[] = jhFinalC(ctx[])

    template jh256Init*(ctx: ptr JH256Ctx): void = jhInitC(ctx[])
    template jh256Input*(ctx: ptr JH256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = jhInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template jh256Final*(ctx: ptr JH256Ctx, output: ptr array[32, uint8]): void = output[] = jhFinalC(ctx[])

    template jh384Init*(ctx: ptr JH384Ctx): void = jhInitC(ctx[])
    template jh384Input*(ctx: ptr JH384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = jhInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template jh384Final*(ctx: ptr JH384Ctx, output: ptr array[48, uint8]): void = output[] = jhFinalC(ctx[])

    template jh512Init*(ctx: ptr JH512Ctx): void = jhInitC(ctx[])
    template jh512Input*(ctx: ptr JH512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = jhInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template jh512Final*(ctx: ptr JH512Ctx, output: ptr array[64, uint8]): void = output[] = jhFinalC(ctx[])

else:
  when Native:
    proc jh224Init*(ctx: var JH224Ctx): void = jhInitC(ctx)
    proc jh224Input*(ctx: var JH224Ctx, input: openArray[uint8]): void = jhInputC(ctx, input)
    proc jh224Final*(ctx: var JH224Ctx): array[28, uint8] = jhFinalC(ctx)

    proc jh256Init*(ctx: var JH256Ctx): void = jhInitC(ctx)
    proc jh256Input*(ctx: var JH256Ctx, input: openArray[uint8]): void = jhInputC(ctx, input)
    proc jh256Final*(ctx: var JH256Ctx): array[32, uint8] = jhFinalC(ctx)

    proc jh384Init*(ctx: var JH384Ctx): void = jhInitC(ctx)
    proc jh384Input*(ctx: var JH384Ctx, input: openArray[uint8]): void = jhInputC(ctx, input)
    proc jh384Final*(ctx: var JH384Ctx): array[48, uint8] = jhFinalC(ctx)

    proc jh512Init*(ctx: var JH512Ctx): void = jhInitC(ctx)
    proc jh512Input*(ctx: var JH512Ctx, input: openArray[uint8]): void = jhInputC(ctx, input)
    proc jh512Final*(ctx: var JH512Ctx): array[64, uint8] = jhFinalC(ctx)

  when defined(c) or defined(objc):
    proc jh224Init*(ctx: ptr JH224Ctx): void {.exportc: "jh224Init".} = jhInitC(ctx[])
    proc jh224Input*(ctx: ptr JH224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "jh224Input".} = jhInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc jh224Final*(ctx: ptr JH224Ctx, output: ptr array[28, uint8]): void {.exportc: "jh224Final".} = output[] = jhFinalC(ctx[])

    proc jh256Init*(ctx: ptr JH256Ctx): void {.exportc: "jh256Init".} = jhInitC(ctx[])
    proc jh256Input*(ctx: ptr JH256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "jh256Input".} = jhInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc jh256Final*(ctx: ptr JH256Ctx, output: ptr array[32, uint8]): void {.exportc: "jh256Final".} = output[] = jhFinalC(ctx[])

    proc jh384Init*(ctx: ptr JH384Ctx): void {.exportc: "jh384Init".} = jhInitC(ctx[])
    proc jh384Input*(ctx: ptr JH384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "jh384Input".} = jhInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc jh384Final*(ctx: ptr JH384Ctx, output: ptr array[48, uint8]): void {.exportc: "jh384Final".} = output[] = jhFinalC(ctx[])

    proc jh512Init*(ctx: ptr JH512Ctx): void {.exportc: "jh512Init".} = jhInitC(ctx[])
    proc jh512Input*(ctx: ptr JH512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "jh512Input".} = jhInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc jh512Final*(ctx: ptr JH512Ctx, output: ptr array[64, uint8]): void {.exportc: "jh512Final".} = output[] = jhFinalC(ctx[])

  elif defined(cpp):
    proc jh224Init*(ctx: ptr JH224Ctx): void {.exportcpp: "jh224Init".} = jhInitC(ctx[])
    proc jh224Input*(ctx: ptr JH224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "jh224Input".} = jhInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc jh224Final*(ctx: ptr JH224Ctx, output: ptr array[28, uint8]): void {.exportcpp: "jh224Final".} = output[] = jhFinalC(ctx[])

    proc jh256Init*(ctx: ptr JH256Ctx): void {.exportcpp: "jh256Init".} = jhInitC(ctx[])
    proc jh256Input*(ctx: ptr JH256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "jh256Input".} = jhInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc jh256Final*(ctx: ptr JH256Ctx, output: ptr array[32, uint8]): void {.exportcpp: "jh256Final".} = output[] = jhFinalC(ctx[])

    proc jh384Init*(ctx: ptr JH384Ctx): void {.exportcpp: "jh384Init".} = jhInitC(ctx[])
    proc jh384Input*(ctx: ptr JH384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "jh384Input".} = jhInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc jh384Final*(ctx: ptr JH384Ctx, output: ptr array[48, uint8]): void {.exportcpp: "jh384Final".} = output[] = jhFinalC(ctx[])

    proc jh512Init*(ctx: ptr JH512Ctx): void {.exportcpp: "jh512Init".} = jhInitC(ctx[])
    proc jh512Input*(ctx: ptr JH512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "jh512Input".} = jhInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc jh512Final*(ctx: ptr JH512Ctx, output: ptr array[64, uint8]): void {.exportcpp: "jh512Final".} = output[] = jhFinalC(ctx[])
