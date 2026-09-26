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

when CPUBits == 64:
  # md4 context for 64 bits
  type
    MD4Ctx* = object
      state*: array[4, uint32]
      length*: uint64
      buffer*: array[64, uint8]
      index*: int

elif CPUBits == 32:
  # md4 context for 32 bits
  type
    MD4Ctx* = object
      state*: array[4, uint32]
      length*: array[2, uint32]
      buffer*: array[64, uint8]
      index*: int
else:
  # md4 context for 8/16 bits
  type
    MD4Ctx* = object
      state*: array[16, uint8]
      length*: array[8, uint8]
      buffer*: array[64, uint8]
      index*: int

when CPUBits == 64 or CPUBits == 32:
  autoMemOpt:
    # declare F sub template
    template F(x, y, z: uint32): uint32 =
      (x and y) or ((not x) and z)

    # declare G sub template
    template G(x, y, z: uint32): uint32 =
      ((x and y) or ((x and z) or (y and z)))

    # declare H sub template
    template H(x, y, z: uint32): uint32 =
      (x xor y xor z)

    # declare FF round template
    template FF(a: var uint32, b, c, d, x, s: uint32): void =
      a += F(b, c, d) + x
      a = rotateLeftBits(a, s)

    # declare GG round template
    template GG(a: var uint32, b, c, d, x, s: uint32): void =
      a += G(b, c, d) + x + 0x5a827999'u32
      a = rotateLeftBits(a, s)

    # declare HH round template
    template HH(a: var uint32, b, c, d, x, s: uint32): void =
      a += H(b, c, d) + x + 0x6ed9eba1'u32
      a = rotateLeftBits(a, s)

    # md4 init core
    template md4InitC(ctx: var MD4Ctx): void {.autoSizeOpt.} =
      when CPUBits == 64:
        ctx.length = 0'u64
      elif CPUBits == 32:
        ctx.length[0] = 0'u32
        ctx.length[1] = 0'u32

      ctx.index = 0

      # initialize state by initialize vector
      ctx.state[0] = 0x67452301'u32
      ctx.state[1] = 0xefcdab89'u32
      ctx.state[2] = 0x98badcfe'u32
      ctx.state[3] = 0x10325476'u32

      # initialize buffer
      zeroMem(addr ctx.buffer[0], 64)

    template md4Transform(state: var array[4, uint32], input: slicearray[64, uint8]): void {.autoSizeOpt.} =
      var chunk: array[16, uint32]
      decodeLE(input, chunk.toSliceArray(0, 15))

      # declare and initialize temporary variables
      var a: uint32 = state[0]
      var b: uint32 = state[1]
      var c: uint32 = state[2]
      var d: uint32 = state[3]

      FF(a, b, c, d, chunk[ 0], 3'u32)
      FF(d, a, b, c, chunk[ 1], 7'u32)
      FF(c, d, a, b, chunk[ 2], 11'u32)
      FF(b, c, d, a, chunk[ 3], 19'u32)
      FF(a, b, c, d, chunk[ 4], 3'u32)
      FF(d, a, b, c, chunk[ 5], 7'u32)
      FF(c, d, a, b, chunk[ 6], 11'u32)
      FF(b, c, d, a, chunk[ 7], 19'u32)
      FF(a, b, c, d, chunk[ 8], 3'u32)
      FF(d, a, b, c, chunk[ 9], 7'u32)
      FF(c, d, a, b, chunk[10], 11'u32)
      FF(b, c, d, a, chunk[11], 19'u32)
      FF(a, b, c, d, chunk[12], 3'u32)
      FF(d, a, b, c, chunk[13], 7'u32)
      FF(c, d, a, b, chunk[14], 11'u32)
      FF(b, c, d, a, chunk[15], 19'u32)

      # call GG round template
      GG(a, b, c, d, chunk[ 0], 3'u32)
      GG(d, a, b, c, chunk[ 4], 5'u32)
      GG(c, d, a, b, chunk[ 8], 9'u32)
      GG(b, c, d, a, chunk[12], 13'u32)
      GG(a, b, c, d, chunk[ 1], 3'u32)
      GG(d, a, b, c, chunk[ 5], 5'u32)
      GG(c, d, a, b, chunk[ 9], 9'u32)
      GG(b, c, d, a, chunk[13], 13'u32)
      GG(a, b, c, d, chunk[ 2], 3'u32)
      GG(d, a, b, c, chunk[ 6], 5'u32)
      GG(c, d, a, b, chunk[10], 9'u32)
      GG(b, c, d, a, chunk[14], 13'u32)
      GG(a, b, c, d, chunk[ 3], 3'u32)
      GG(d, a, b, c, chunk[ 7], 5'u32)
      GG(c, d, a, b, chunk[11], 9'u32)
      GG(b, c, d, a, chunk[15], 13'u32)

      # call HH round template
      HH(a, b, c, d, chunk[ 0], 3'u32)
      HH(d, a, b, c, chunk[ 8], 9'u32)
      HH(c, d, a, b, chunk[ 4], 11'u32)
      HH(b, c, d, a, chunk[12], 15'u32)
      HH(a, b, c, d, chunk[ 2], 3'u32)
      HH(d, a, b, c, chunk[10], 9'u32)
      HH(c, d, a, b, chunk[ 6], 11'u32)
      HH(b, c, d, a, chunk[14], 15'u32)
      HH(a, b, c, d, chunk[ 1], 3'u32)
      HH(d, a, b, c, chunk[ 9], 9'u32)
      HH(c, d, a, b, chunk[ 5], 11'u32)
      HH(b, c, d, a, chunk[13], 15'u32)
      HH(a, b, c, d, chunk[ 3], 3'u32)
      HH(d, a, b, c, chunk[11], 9'u32)
      HH(c, d, a, b, chunk[ 7], 11'u32)
      HH(b, c, d, a, chunk[15], 15'u32)

      # add and assign temporary variables to
      state[0] += a
      state[1] += b
      state[2] += c
      state[3] += d

    # md4 input core
    template md4InputC(ctx: var MD4Ctx, input: openArray[uint8]): void =
      # set inputLen and index
      var inputLen: int = input.len

      var check: bool = true

      if inputLen <= 0: check = false

      if check:
        # set inputLen, index and add inputLen to ctx.length
        var index: int = ctx.index
        when CPUBits == 64:
          ctx.length += inputLen.uint64
        elif CPUBits == 32:
          let oldLength: uint32 = ctx.length[0]
          ctx.length[0] += uint32(inputLen)
          if ctx.length[0] < oldLength:
            ctx.length[1] += 1

        # set left and take
        let left: int = 64 - index
        var position: int = 0

        if inputLen >= left:
          if left > 0:
            copyMem(addr ctx.buffer[index], addr input[0], left)
          md4Transform(ctx.state, ctx.buffer.toSliceArray(0, 63))
          position = left
          index = 0

          while position + 64 <= inputLen:
            md4Transform(ctx.state, input.toSliceArray(position, position + 63, 64))
            position += 64

        let remain: int = inputLen - position
        if remain > 0:
          copyMem(addr ctx.buffer[index], addr input[position], remain)
          index += remain

        ctx.index = index

    # md4 final core
    template md4FinalC(ctx: var MD4Ctx): array[16, uint8] =
      # declare output
      var output: array[16, uint8]

      # set index
      var index: int = ctx.index

      # add padding
      ctx.buffer[index] = 0x80'u8
      index.inc

      # set padding length
      let padLen: int = if index <= 56: 56 - index else: 64 - index

      # if index is smaller then 56
      if index <= 56:
        # zerofill buffer until 56
        zeroMem(addr ctx.buffer[index], padLen)
      else:
        if padLen > 0:
          # zerofill buffer until 64
          zeroMem(addr ctx.buffer[index], padLen)
        # call transform
        md4Transform(ctx.state, ctx.buffer.toSliceArray(0, 63))
        # zerofill buffer until 56
        zeroMem(addr ctx.buffer[0], 56)

      # multiple 8 to ctx.length and copy to ctx.buffer
      when CPUBits == 64:
        ctx.length = ctx.length shl 3
        toBytesLE(ctx.length, ctx.buffer.toSliceArray(56, 63))
      elif CPUBits == 32:
        ctx.length[1] = (ctx.length[0] shr 29) or (ctx.length[1] shl 3)
        ctx.length[0] = ctx.length[0] shl 3
        encodeLE(ctx.length.toSliceArray(0, 1), ctx.buffer.toSliceArray(56, 63))

      # call md4 transform template by endian
      md4Transform(ctx.state, ctx.buffer.toSliceArray(0, 63))

      # encode state to output
      when LE and Native:
        copyMem(addr output, addr ctx.state, 16)
      else:
        encodeLE(ctx.state, output)

      output

# export wrappers
when defined(templateOpt):
  template md4Init*(ctx: var MD4Ctx): void = md4InitC(ctx)
  template md4Input*(ctx: var MD4Ctx, input: openArray[uint8]): void = md4InputC(ctx, input)
  template md4Final*(ctx: var MD4Ctx): array[16, uint8] = md4FinalC(ctx)

  when Native:
    template md4Init*(ctx: ptr MD4Ctx): void = md4InitC(ctx[])
    template md4Input*(ctx: ptr MD4Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = md4InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template md4Final*(ctx: ptr MD4Ctx, output: ptr array[16, uint8]): void = output[] = md4FinalC(ctx[])
else:
  when Native:
    proc md4Init*(ctx: var MD4Ctx): void = md4InitC(ctx)
    proc md4Input*(ctx: var MD4Ctx, input: openArray[uint8]): void = md4InputC(ctx, input)
    proc md4Final*(ctx: var MD4Ctx): array[16, uint8] = md4FinalC(ctx)

  when defined(c) or defined(objc):
    proc md4Init*(ctx: ptr MD4Ctx): void {.exportc: "md4Init".} = md4InitC(ctx[])
    proc md4Input*(ctx: ptr MD4Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "md4Input".} = md4InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc md4Final*(ctx: ptr MD4Ctx, output: ptr array[16, uint8]): void {.exportc: "md4Final".} = output[] = md4FinalC(ctx[])
  elif defined(cpp):
    proc md4Init*(ctx: ptr MD4Ctx): void {.exportcpp: "md4Init".} = md4InitC(ctx[])
    proc md4Input*(ctx: ptr MD4Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "md4Input".} = md4InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc md4Final*(ctx: ptr MD4Ctx, output: ptr array[16, uint8]): void {.exportcpp: "md4Final".} = output[] = md4FinalC(ctx[])
