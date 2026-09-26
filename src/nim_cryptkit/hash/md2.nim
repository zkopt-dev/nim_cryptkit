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

type
  MD2Ctx* = object
    state*: array[48, uint8]
    checksum*: array[16, uint8]
    buffer*: array[16, uint8]
    count*: int

# constant
# PISubst : PI based constant
const
  PISubst: array[256, uint8] = [
  41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 19,
  98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188, 76, 130, 202,
  30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24, 138, 23, 229, 18,
  190, 78, 196, 214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47, 238, 122,
  169, 104, 121, 145, 21, 178, 7, 63, 148, 194, 16, 137, 11, 34, 95, 33,
  128, 127, 93, 154, 90, 144, 50, 39, 53, 62, 204, 231, 191, 247, 151, 3,
  255, 25, 48, 179, 72, 165, 181, 209, 215, 94, 146, 42, 172, 86, 170, 198,
  79, 184, 56, 210, 150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241,
  69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2,
  27, 96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
  85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197, 234, 38,
  44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65, 129, 77, 82,
  106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123, 8, 12, 189, 177, 74,
  120, 136, 149, 139, 227, 99, 232, 109, 233, 203, 213, 254, 59, 0, 29, 57,
  242, 239, 183, 14, 102, 88, 208, 228, 166, 119, 114, 248, 235, 117, 75, 10,
  49, 68, 80, 180, 143, 237, 31, 26, 219, 153, 141, 51, 159, 17, 131, 20
  ]

autoMemOpt:
  # md2 transform part
  template md2Transform(ctx: var MD2Ctx, input: slicearray[16, uint8]): void =
    # copy input and extend ctx's state
    for i in static(0 ..< 16):
      ctx.state[i + 16] = input[i]
      ctx.state[i + 32] = ctx.state[i] xor input[i]

    var temp: uint8 = 0
    # calculate block to temp value
    for i in static(0 ..< 18):
      for j in static(0 ..< 48):
        ctx.state[j] = ctx.state[j] xor PISubst[temp.int]
        temp = ctx.state[j]
      temp = (temp + i.uint8) and 0xFF'u8

    # add temp value
    var l: uint8 = ctx.checksum[15]
    for i in static(0 ..< 16):
      ctx.checksum[i] = ctx.checksum[i] xor PISubst[(input[i] xor l).int]
      l = ctx.checksum[i]

  # md2 init core
  template md2InitC(ctx: var MD2Ctx): void =
    # count to zero
    ctx.count = 0
    # zerofill ctx's state
    zeroMem(addr ctx.state[0], 48)
    # zerofill ctx's checksum
    zeroMem(addr ctx.checksum[0], 16)
    # zerofill ctx's buffer
    zeroMem(addr ctx.buffer[0], 16)

  # md2 input core
  template md2InputC(ctx: var MD2Ctx, input: openArray[uint8]): void =
    # set position variables
    var position: int = 0

    # set input length
    let inputLen: int = input.len

    # if ctx's count is bigger then zero
    if ctx.count > 0:
      # set mount to take
      let take: int = min(inputLen, 16 - ctx.count)
      # copy input to ctx.buffer[count]
      copyMem(addr ctx.buffer[ctx.count], unsafeAddr input[0], take)
      # add take to position and ctx.count
      ctx.count += take
      position += take

      # if count is 16
      if ctx.count == 16:
        # call md2 transform template
        md2Transform(ctx, ctx.buffer.toSliceArray(0, 15))
        # set count to zero
        ctx.count = 0

    # while position is smaller then input length - 16
    while position + 16 <= inputLen:
      # call md2 transform template
      md2Transform(ctx, input.toSliceArray(position, position + 15, 16))
      # add 16(block size) to position
      position += 16

    # calculate rest
    let rest: int = inputLen - position
    # if rest is bigger then 0
    if rest > 0:
      # copy input to ctx.buffer
      copyMem(addr ctx.buffer[0], addr input[position], rest)
      # set ctx.count to rest
      ctx.count = rest

  # md2 final core
  template md2FinalC(ctx: var MD2Ctx): array[16, uint8] =
    # declare output
    var output: array[16, uint8]
    # padding length
    let padLen = 16 - ctx.count
    # set padding value
    let padValue: uint8 = uint8(padLen)

    # add padding
    for i in ctx.count ..< 16:
      ctx.buffer[i] = padValue

    # call md2 transform template by buffer
    md2Transform(ctx, ctx.buffer.toSliceArray(0, 15))

    # call md2 transform template by checksum
    md2Transform(ctx, ctx.checksum.toSliceArray(0, 15))

    # copy ctx.state to output
    copyMem(addr output[0], addr ctx.state[0], 16)

    output

# export wrappers
when defined(templateOpt):
  template md2Init*(ctx: var MD2Ctx): void = md2InitC(ctx)
  template md2Input*(ctx: var MD2Ctx, input: openArray[uint8]): void = md2InputC(ctx, input)
  template md2Final*(ctx: var MD2Ctx): array[16, uint8] = md2FinalC(ctx)

  when Native:
    template md2Init*(ctx: ptr MD2Ctx): void = md2InitC(ctx[])
    template md2Input*(ctx: ptr MD2Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = md2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template md2Final*(ctx: ptr MD2Ctx, output: ptr array[16, uint8]): void = output[] =  md2FinalC(ctx[])
else:
  when Native:
    proc md2Init*(ctx: var MD2Ctx): void = md2InitC(ctx)
    proc md2Input*(ctx: var MD2Ctx, input: openArray[uint8]): void = md2InputC(ctx, input)
    proc md2Final*(ctx: var MD2Ctx): array[16, uint8] = md2FinalC(ctx)

  when defined(c) or defined(objc):
    proc md2Init*(ctx: ptr MD2Ctx): void {.exportc: "md2Init".} = md2InitC(ctx[])
    proc md2Input*(ctx: ptr MD2Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "md2Input".} = md2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc md2Final*(ctx: ptr MD2Ctx, output: ptr array[16, uint8]): void {.exportc: "md2Final".} = output[] =  md2FinalC(ctx[])
  elif defined(cpp):
    proc md2Init*(ctx: ptr MD2Ctx): void {.exportcpp: "md2Init".} = md2InitC(ctx[])
    proc md2Input*(ctx: ptr MD2Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "md2Input".} = md2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc md2Final*(ctx: ptr MD2Ctx, output: ptr array[16, uint8]): void {.exportcpp: "md2Final".} = output[] =  md2FinalC(ctx[])
