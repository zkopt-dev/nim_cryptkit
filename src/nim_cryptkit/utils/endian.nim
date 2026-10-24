when not defined(nostd):
  import std/bitops
  import std/endians
import envconst
import slicearray
import optmacro

type
  BigUint = concept u
    u is (uint16|uint32|uint64)

template getB0*(a: uint16): int = int((a shr 0) and 0xFF'u16)
template getB1*(a: uint16): int = int((a shr 8) and 0xFF'u16)

template getB0*(a: uint32): int = int((a shr 0) and 0xFF'u32)
template getB1*(a: uint32): int = int((a shr 8) and 0xFF'u32)
template getB2*(a: uint32): int = int((a shr 16) and 0xFF'u32)
template getB3*(a: uint32): int = int((a shr 24) and 0xFF'u32)

template getB0*(a: uint64): int = int((a shr 0) and 0xFF'u64)
template getB1*(a: uint64): int = int((a shr 8) and 0xFF'u64)
template getB2*(a: uint64): int = int((a shr 16) and 0xFF'u64)
template getB3*(a: uint64): int = int((a shr 24) and 0xFF'u64)
template getB4*(a: uint64): int = int((a shr 32) and 0xFF'u64)
template getB5*(a: uint64): int = int((a shr 40) and 0xFF'u64)
template getB6*(a: uint64): int = int((a shr 48) and 0xFF'u64)
template getB7*(a: uint64): int = int((a shr 56) and 0xFF'u64)

when defined(nostd):
  when defined(js):
    template swapEndian64*(outp, inp: pointer) =
      let val = cast[ptr uint64](inp)[]

      cast[ptr uint64](outp)[] =
        ((val and 0x00000000000000FF'u64) shl 56) or
        ((val and 0x000000000000FF00'u64) shl 40) or
        ((val and 0x0000000000FF0000'u64) shl 24) or
        ((val and 0x00000000FF000000'u64) shl 8)  or
        ((val and 0x000000FF00000000'u64) shr 8)  or
        ((val and 0x0000FF0000000000'u64) shr 24) or
        ((val and 0x00FF000000000000'u64) shr 40) or
        ((val and 0xFF00000000000000'u64) shr 56)

    template swapEndian32*(outp, inp: pointer) =
      let val = cast[ptr uint32](inp)[]

      cast[ptr uint32](outp)[] =
        ((val and 0x000000FF'u32) shl 24) or
        ((val and 0x0000FF00'u32) shl 8)  or
        ((val and 0x00FF0000'u32) shr 8)  or
        ((val and 0xFF000000'u32) shr 24)

    template swapEndian16*(outp, inp: pointer) =
      let val = cast[ptr uint16](inp)[]

      cast[ptr uint16](outp)[] =
        ((val and 0x00FF'u16) shl 8) or
        ((val and 0xFF00'u16) shr 8)
  else:
    template swapEndian64*(outp, inp: pointer) =
      var i = cast[cstring](inp)
      var o = cast[cstring](outp)
      o[0] = i[7]
      o[1] = i[6]
      o[2] = i[5]
      o[3] = i[4]
      o[4] = i[3]
      o[5] = i[2]
      o[6] = i[1]
      o[7] = i[0]

    template swapEndian32*(outp, inp: pointer) =
      var i = cast[cstring](inp)
      var o = cast[cstring](outp)
      o[0] = i[3]
      o[1] = i[2]
      o[2] = i[1]
      o[3] = i[0]

    template swapEndian16*(outp, inp: pointer) =
      var i = cast[cstring](inp)
      var o = cast[cstring](outp)
      o[0] = i[1]
      o[1] = i[0]

  when BE:
    template littleEndian64*(outp, inp: pointer): void = swapEndian64(outp, inp)
    template littleEndian32*(outp, inp: pointer): void = swapEndian32(outp, inp)
    template littleEndian16*(outp, inp: pointer): void = swapEndian16(outp, inp)
    template bigEndian64*(outp, inp: pointer): void = unroll(i, 0, 7): outp[i] = inp[i]
    template bigEndian32*(outp, inp: pointer): void = unroll(i, 0, 3): outp[i] = inp[i]
    template bigEndian16*(outp, inp: pointer): void = unroll(i, 0, 1): outp[i] = inp[i]
  else:
    template littleEndian64*(outp, inp: pointer): void = unroll(i, 0, 7): outp[i] = inp[i]
    template littleEndian32*(outp, inp: pointer): void = unroll(i, 0, 3): outp[i] = inp[i]
    template littleEndian16*(outp, inp: pointer): void = unroll(i, 0, 1): outp[i] = inp[i]
    template bigEndian64*(outp, inp: pointer): void = swapEndian64(outp, inp)
    template bigEndian32*(outp, inp: pointer): void = swapEndian32(outp, inp)
    template bigEndian16*(outp, inp: pointer): void = swapEndian16(outp, inp)

# swapEndian : swap endian
# use Nim's default swapEndian code
template swapEndian*[T: SomeUnsignedInt](input: T, output: var T): void {.autoSizeOpt.} =
  when T is uint64:
    swapEndian64(addr output, addr input)
  elif T is uint32:
    swapEndian32(addr output, addr input)
  elif T is uint16:
    swapEndian16(addr output, addr input)
  else:
    output = input

# swapEndian : array version
template swapEndian*[T: SomeUnsignedInt, N: static int](input: array[N, T], output: var array[N, T]): void {.autoSizeOpt.} =
  unroll(i, 0, N - 1):
    swapEndian(input[i], output[i])

# swapEndian : openArray version
template swapEndian*[T: SomeUnsignedInt, N: static int](input: openArray[T], output: var openArray[T]): void {.autoSizeOpt.} =
  for i in 0 ..< input.len:
    swapEndian(input[i], output[i])

# swapEndian : openArray and static length version
template swapEndian*[T: SomeUnsignedInt, N: static int](input: openArray[T], output: var openArray[T], length: static int): void {.autoSizeOpt.} =
  unroll(i, 0, length - 1):
    swapEndian(input[i], output[i])

# swapEndian : slicearray version
template swapEndian*[T: SomeUnsignedInt, N: static int](input, output: slicearray[N, T]): void {.autoSizeOpt.} =
  unroll(i, 0, N - 1):
    swapEndian(input[i], output[i])

# swapEndian : ptr array version
template swapEndian*[T: SomeUnsignedInt, N: static int](input: ptr array[N, T], output: ptr array[N, T]): void {.autoSizeOpt.} =
  unroll(i, 0, N - 1):
    swapEndian(input[i], output[i])

# swapEndian : ptr UncheckedArray version
template swapEndian*[T: BigUint](input: ptr UncheckedArray[T], output: ptr UncheckedArray[T], length: int): void {.autoSizeOpt.} =
  for i in 0 ..< length:
    swapEndian(input[i], output[i])

# swapEndian : ptr UncheckedArray and static length version
template swapEndian*[T: BigUint](input: ptr UncheckedArray[T], output: ptr UncheckedArray[T], length: static int): void {.autoSizeOpt.} =
  unroll(i, 0, length - 1):
    swapEndian(input[i], output[i])

# toLE : to little endian generic function
# use Nim's default littleEndian code
template toLE*[T: SomeUnsignedInt](input: T, output: var T): void {.autoSizeOpt.} =
  when T is uint64:
    littleEndian64(addr output, addr input)
  elif T is uint32:
    littleEndian32(addr output, addr input)
  elif T is uint16:
    littleEndian16(addr output, addr input)
  else:
    output = input

# toBE : to big endian generic function
# use Nim's default bigEndian code
template toBE*[T: SomeUnsignedInt](input: T, output: var T): void {.autoSizeOpt.} =
  when T is uint64:
    bigEndian64(addr output, addr input)
  elif T is uint32:
    bigEndian32(addr output, addr input)
  elif T is uint16:
    bigEndian16(addr output, addr input)
  else:
    output = input

# beToNative : big endian to native endian
# warning : input's endian must be big endian
# mutable parameter version
# single variable version
template beToNative*[T: BigUint](input: T, output: var T): void {.autoSizeOpt.} =
  when cpuEndian == littleEndian:
    swapEndian(input, output)
  else:
    output = input

# beToNative : big endian to native endian
# warning : input's endian must be big endian
# return value version
# single variable version
template beToNative*[T: BigUint](input: T): T {.autoSizeOpt.} =
  var output: T
  when cpuEndian == littleEndian:
    swapEndian(input, output)
  else:
    output = input

# beToNative : big endian to native endian
# warning : input's endian must be big endian
# mutable parameter version
# array version
template beToNative*[T: BigUint, N: static int](input: array[N, T], output: var array[N, T]): void {.autoSizeOpt.} =
  unroll(i, 0, N - 1):
    beToNative(input[i], output[i])

# beToNative : big endian to native endian
# warning : input's endian must be big endian
# return value version
# array version
template beToNative*[T: BigUint, N: static int](input: array[N, T]): array[N, T] {.autoSizeOpt.} =
  var output: array[N, T]
  unroll(i, 0, N - 1):
    beToNative(input[i], output[i])
  output

# beToNative : big endian to native endian
# warning : input's endian must be big endian
# mutable parameter version
# openArray version
template beToNative*[T: BigUint](input: openArray[T], output: var openArray[T]): void {.autoSizeOpt.} =
  for i in 0 ..< input.len:
    beToNative(input[i], output[i])

# beToNative : big endian to native endian
# warning : input's endian must be big endian
# return value version
# openArray version
template beToNative*[T: BigUint](input: openArray[T]): openArray[T] {.autoSizeOpt.} =
  var output: seq[T] = newSeq[T](input.len)
  for i in 0 ..< input.len:
    beToNative(input[i], output[i])
  output

# beToNative : big endian to native endian
# warning : input's endian must be big endian
# mutable parameter version
# openArray and static length version
template beToNative*[T: BigUint](input: openArray[T], output: var openArray[T], length: static int): void {.autoSizeOpt.} =
  unroll(i, 0, length - 1):
    beToNative(input[i], output[i])

# beToNative : big endian to native endian
# warning : input's endian must be big endian
# return value version
# openArray and static length version
template beToNative*[T: BigUint](input: openArray[T], length: static int): openArray[T] {.autoSizeOpt.} =
  var output: seq[T] = newSeq[T](input.len)
  for i in 0 ..< input.len:
    beToNative(input[i], output[i])
  output

# beToNative : big endian to native endian
# warning : input's endian must be big endian
# mutable parameter version
# slicearray version
template beToNative*[T: BigUint, N: static int](input, output: slicearray[N, T]): void {.autoSizeOpt.} =
  unroll(i, 0, N - 1):
    beToNative(input[i], output[i])

# beToNative : big endian to native endian
# warning : input's endian must be big endian
# return value version
# slicearray version
template beToNative*[T: BigUint, N: static int](input: slicearray[N, T]): array[N, T] {.autoSizeOpt.} =
  var output: array[N, T]
  unroll(i, 0, N - 1):
    beToNative(input[i], output[i])
  output

# beToNative : big endian to native endian
# warning : input's endian must be big endian
# mutable parameter version
# ptr array version
template beToNative*[T: BigUint, N: static int](input: ptr array[N, T], output: ptr array[N, T]): void {.autoSizeOpt.} =
  unroll(i, 0, N - 1):
    beToNative(input[i], output[i])

# beToNative : big endian to native endian
# warning : input's endian must be big endian
# return value version
# ptr array version
template beToNative*[T: BigUint, N: static int](input: ptr array[N, T]): array[N, T] {.autoSizeOpt.} =
  var output: array[N, T]
  unroll(i, 0, N - 1):
    beToNative(input[i], output[i])
  output

# beToNative : big endian to native endian
# warning : input's endian must be big endian
# mutable parameter version
# ptr UncheckedArray version
template beToNative*[T: BigUint](input: ptr UncheckedArray[T], output: ptr UncheckedArray[T], length: int): void {.autoSizeOpt.} =
  for i in 0 ..< length:
    beToNative(input[i], output[i])

# beToNative : big endian to native endian
# warning : input's endian must be big endian
# return value version
# ptr UncheckedArray version
template beToNative*[T: BigUint](input: ptr UncheckedArray[T], length: int): seq[T] {.autoSizeOpt.} =
  var output: seq[T] = newSeq[T](length)
  for i in 0 ..< length:
    beToNative(input[i], output[i])
  output

# beToNative : big endian to native endian
# warning : input's endian must be big endian
# mutable parameter version
# ptr UncheckedArray and static length version
template beToNative*[T: BigUint](input: ptr UncheckedArray[T], output: ptr UncheckedArray[T], length: static int): void {.autoSizeOpt.} =
  unroll(i, 0, length - 1):
    beToNative(input[i], output[i])

# beToNative : big endian to native endian
# warning : input's endian must be big endian
# return value version
# ptr UncheckedArray and static length version
template beToNative*[T: BigUint](input: ptr UncheckedArray[T], length: static int): array[length, T] {.autoSizeOpt.} =
  var output: array[length, T]
  unroll(i, 0, length - 1):
    beToNative(input[i], output[i])
  output

# nativeToBE : native endian to big endian
# warning : input's endian must be native endian
# mutable parameter version
# single variable version
template nativeToBE*[T: BigUint](input: T, output: var T): void {.autoSizeOpt.} =
  when cpuEndian == littleEndian:
    swapEndian(input, output)
  else:
    output = input

# nativeToBE : native endian to big endian
# warning : input's endian must be native endian
# return value version
# single variable version
template nativeToBE*[T: BigUint](input: T): T {.autoSizeOpt.} =
  var output: T
  when cpuEndian == littleEndian:
    swapEndian(input, output)
  else:
    output = input
  output

# nativeToBE : native endian to big endian
# warning : input's endian must be native endian
# mutable parameter version
# array version
template nativeToBE*[T: BigUint, N: static int](input: array[N, T], output: var array[N, T]): void {.autoSizeOpt.} =
  unroll(i, 0, N - 1):
    nativeToBE(input[i], output[i])

# nativeToBE : native endian to big endian
# warning : input's endian must be big endian
# return value version
# array version
template nativeToBE*[T: BigUint, N: static int](input: array[N, T]): array[N, T] {.autoSizeOpt.} =
  var output: array[N, T]
  unroll(i, 0, N - 1):
    nativeToBE(input[i], output[i])
  output

# nativeToBE : native endian to big endian
# warning : input's endian must be native endian
# mutable parameter version
# openArray version
template nativeToBE*[T: BigUint](input: openArray[T], output: var openArray[T]): void {.autoSizeOpt.} =
  for i in 0 ..< input.len:
    nativeToBE(input[i], output[i])

# nativeToBE : native endian to big endian
# warning : input's endian must be native endian
# return value version
# openArray version
template nativeToBE*[T: BigUint](input: openArray[T]): openArray[T] {.autoSizeOpt.} =
  var output: seq[T] = newSeq[T](input.len)
  for i in 0 ..< input.len:
    nativeToBE(input[i], output[i])
  output

# nativeToBE : native endian to big endian
# warning : input's endian must be native endian
# mutable parameter version
# openArray and static length version
template nativeToBE*[T: BigUint](input: openArray[T], output: var openArray[T], length: static int): void {.autoSizeOpt.} =
  unroll(i, 0, length - 1):
    nativeToBE(input[i], output[i])

# nativeToBE : native endian to big endian
# warning : input's endian must be native endian
# return value version
# openArray and static length version
template nativeToBE*[T: BigUint](input: openArray[T], length: static int): openArray[T] {.autoSizeOpt.} =
  var output: seq[T] = newSeq[T](input.len)
  for i in 0 ..< input.len:
    nativeToBE(input[i], output[i])
  output

# nativeToBE : native endian to big endian
# warning : input's endian must be native endian
# mutable parameter version
# slicearray version
template nativeToBE*[T: BigUint, N: static int](input, output: slicearray[N, T]): void {.autoSizeOpt.} =
  unroll(i, 0, N - 1):
    nativeToBE(input[i], output[i])

# nativeToBE : native endian to big endian
# warning : input's endian must be native endian
# return value version
# slicearray version
template nativeToBE*[T: BigUint, N: static int](input: slicearray[N, T]): array[N, T] {.autoSizeOpt.} =
  var output: array[N, T]
  unroll(i, 0, N - 1):
    nativeToBE(input[i], output[i])
  output

# nativeToBE : native endian to big endian
# warning : input's endian must be native endian
# mutable parameter version
# ptr array version
template nativeToBE*[T: BigUint, N: static int](input: ptr array[N, T], output: ptr array[N, T]): void {.autoSizeOpt.} =
  unroll(i, 0, N - 1):
    nativeToBE(input[i], output[i])

# nativeToBE : native endian to big endian
# warning : input's endian must be native endian
# return value version
# ptr array version
template nativeToBE*[T: BigUint, N: static int](input: ptr array[N, T]): array[N, T] {.autoSizeOpt.} =
  var output: array[N, T]
  unroll(i, 0, N - 1):
    nativeToBE(input[i], output[i])
  output

# nativeToBE : native endian to big endian
# warning : input's endian must be native endian
# mutable parameter version
# ptr UncheckedArray version
template nativeToBE*[T: BigUint](input: ptr UncheckedArray[T], output: ptr UncheckedArray[T], length: int): void {.autoSizeOpt.} =
  for i in 0 ..< length:
    nativeToBE(input[i], output[i])

# nativeToBE : native endian to big endian
# warning : input's endian must be native endian
# return value version
# ptr UncheckedArray version
template nativeToBE*[T: BigUint](input: ptr UncheckedArray[T], length: int): seq[T] {.autoSizeOpt.} =
  var output: seq[T] = newSeq[T](length)
  for i in 0 ..< length:
    nativeToBE(input[i], output[i])
  output

# nativeToBE : native endian to big endian
# warning : input's endian must be native endian
# mutable parameter version
# ptr UncheckedArray and static length version
template nativeToBE*[T: BigUint](input: ptr UncheckedArray[T], output: ptr UncheckedArray[T], length: static int): void {.autoSizeOpt.} =
  unroll(i, 0, length - 1):
    nativeToBE(input[i], output[i])

# nativeToBE : native endian to big endian
# warning : input's endian must be native endian
# return value version
# ptr UncheckedArray and static length version
template nativeToBE*[T: BigUint](input: ptr UncheckedArray[T], length: static int): array[length, T] {.autoSizeOpt.} =
  var output: array[length, T]
  unroll(i, 0, length - 1):
    nativeToBE(input[i], output[i])
  output

# leToNative : little endian to native endian
# warning : input's endian must be little endian
# mutable parameter version
# single variable version
template leToNative*[T: BigUint](input: T, output: var T): void {.autoSizeOpt.} =
  when cpuEndian == bigEndian:
    swapEndian(input, output)
  else:
    output = input

# leToNative : little endian to native endian
# warning : input's endian must be little endian
# return value version
# single variable version
template leToNative*[T: BigUint](input: T): T {.autoSizeOpt.} =
  var output: T
  when cpuEndian == bigEndian:
    swapEndian(input, output)
  else:
    output = input
  output

# leToNative : little endian to native endian
# warning : input's endian must be little endian
# mutable parameter version
# array version
template leToNative*[T: BigUint, N: static int](input: array[N, T], output: var array[N, T]): void {.autoSizeOpt.} =
  unroll(i, 0, N - 1):
    leToNative(input[i], output[i])

# leToNative : little endian to native endian
# warning : input's endian must be little endian
# return value version
# array version
template leToNative*[T: BigUint, N: static int](input: array[N, T]): array[N, T] {.autoSizeOpt.} =
  var output: array[N, T]
  unroll(i, 0, N - 1):
    leToNative(input[i], output[i])
  output

# leToNative : little endian to native endian
# warning : input's endian must be little endian
# mutable parameter version
# openArray version
template leToNative*[T: BigUint](input: openArray[T], output: var openArray[T]): void {.autoSizeOpt.} =
  for i in 0 ..< input.len:
    leToNative(input[i], output[i])

# leToNative : little endian to native endian
# warning : input's endian must be little endian
# return value version
# openArray version
template leToNative*[T: BigUint](input: openArray[T]): openArray[T] {.autoSizeOpt.} =
  var output: seq[T] = newSeq[T](input.len)
  for i in 0 ..< input.len:
    leToNative(input[i], output[i])
  output

# leToNative : little endian to native endian
# warning : input's endian must be little endian
# mutable parameter version
# openArray and static length version
template leToNative*[T: BigUint](input: openArray[T], output: var openArray[T], length: static int): void {.autoSizeOpt.} =
  unroll(i, 0, length - 1):
    leToNative(input[i], output[i])

# leToNative : little endian to native endian
# warning : input's endian must be little endian
# return value version
# openArray and static length version
template leToNative*[T: BigUint](input: openArray[T], length: static int): openArray[T] {.autoSizeOpt.} =
  var output: seq[T] = newSeq[T](input.len)
  for i in 0 ..< input.len:
    leToNative(input[i], output[i])
  output

# leToNative : little endian to native endian
# warning : input's endian must be little endian
# mutable parameter version
# slicearray version
template leToNative*[T: BigUint, N: static int](input, output: slicearray[N, T]): void {.autoSizeOpt.} =
  unroll(i, 0, N - 1):
    leToNative(input[i], output[i])

# leToNative : little endian to native endian
# warning : input's endian must be little endian
# return value version
# slicearray version
template leToNative*[T: BigUint, N: static int](input: slicearray[N, T]): array[N, T] {.autoSizeOpt.} =
  var output: array[N, T]
  unroll(i, 0, N - 1):
    leToNative(input[i], output[i])
  output

# leToNative : little endian to native endian
# warning : input's endian must be little endian
# mutable parameter version
# ptr array version
template leToNative*[T: BigUint, N: static int](input: ptr array[N, T], output: ptr array[N, T]): void {.autoSizeOpt.} =
  unroll(i, 0, N - 1):
    leToNative(input[i], output[i])

# leToNative : little endian to native endian
# warning : input's endian must be little endian
# return value version
# ptr array version
template leToNative*[T: BigUint, N: static int](input: ptr array[N, T]): array[N, T] {.autoSizeOpt.} =
  var output: array[N, T]
  unroll(i, 0, N - 1):
    leToNative(input[i], output[i])
  output

# leToNative : little endian to native endian
# warning : input's endian must be little endian
# mutable parameter version
# ptr UncheckedArray version
template leToNative*[T: BigUint](input: ptr UncheckedArray[T], output: ptr UncheckedArray[T], length: int): void {.autoSizeOpt.} =
  for i in 0 ..< length:
    leToNative(input[i], output[i])

# leToNative : little endian to native endian
# warning : input's endian must be little endian
# return value version
# ptr UncheckedArray version
template leToNative*[T: BigUint](input: ptr UncheckedArray[T], length: int): seq[T] {.autoSizeOpt.} =
  var output: seq[T] = newSeq[T](length)
  for i in 0 ..< length:
    leToNative(input[i], output[i])
  output

# leToNative : little endian to native endian
# warning : input's endian must be little endian
# mutable parameter version
# ptr UncheckedArray and static length version
template leToNative*[T: BigUint](input: ptr UncheckedArray[T], output: ptr UncheckedArray[T], length: static int): void {.autoSizeOpt.} =
  unroll(i, 0, length - 1):
    leToNative(input[i], output[i])

# leToNative : little endian to native endian
# warning : input's endian must be little endian
# return value version
# ptr UncheckedArray and static length version
template leToNative*[T: BigUint](input: ptr UncheckedArray[T], length: static int): array[length, T] {.autoSizeOpt.} =
  var output: array[length, T]
  unroll(i, 0, length - 1):
    leToNative(input[i], output[i])
  output

# nativeToLE : native endian to little endian
# warning : input's endian must be native endian
# mutable parameter version
# single variable version
template nativeToLE*[T: BigUint](input: T, output: var T): void {.autoSizeOpt.} =
  when cpuEndian == bigEndian:
    swapEndian(input, output)
  else:
    output = input

# nativeToLE : native endian to little endian
# warning : input's endian must be native endian
# return value version
# single variable version
template nativeToLE*[T: BigUint](input: T): T {.autoSizeOpt.} =
  var output: T
  when cpuEndian == bigEndian:
    swapEndian(input, output)
  else:
    output = input
  output

# nativeToLE : native endian to little endian
# warning : input's endian must be native endian
# mutable parameter version
# array version
template nativeToLE*[T: BigUint, N: static int](input: array[N, T], output: var array[N, T]): void {.autoSizeOpt.} =
  unroll(i, 0, N - 1):
    nativeToLE(input[i], output[i])

# nativeToLE : native endian to little endian
# warning : input's endian must be native endian
# return value version
# array version
template nativeToLE*[T: BigUint, N: static int](input: array[N, T]): array[N, T] {.autoSizeOpt.} =
  var output: array[N, T]
  unroll(i, 0, N - 1):
    nativeToLE(input[i], output[i])
  output

# nativeToLE : native endian to little endian
# warning : input's endian must be native endian
# mutable parameter version
# openArray version
template nativeToLE*[T: BigUint](input: openArray[T], output: var openArray[T]): void {.autoSizeOpt.} =
  for i in 0 ..< input.len:
    nativeToLE(input[i], output[i])

# nativeToLE : native endian to little endian
# warning : input's endian must be native endian
# return value version
# openArray version
template nativeToLE*[T: BigUint](input: openArray[T]): openArray[T] {.autoSizeOpt.} =
  var output: seq[T] = newSeq[T](input.len)
  for i in 0 ..< input.len:
    nativeToLE(input[i], output[i])
  output

# nativeToLE : native endian to little endian
# warning : input's endian must be native endian
# mutable parameter version
# openArray and static length version
template nativeToLE*[T: BigUint](input: openArray[T], output: var openArray[T], length: static int): void {.autoSizeOpt.} =
  unroll(i, 0, length - 1):
    nativeToLE(input[i], output[i])

# nativeToLE : native endian to little endian
# warning : input's endian must be little endian
# return value version
# openArray and static length version
template nativeToLE*[T: BigUint](input: openArray[T], length: static int): openArray[T] {.autoSizeOpt.} =
  var output: seq[T] = newSeq[T](input.len)
  for i in 0 ..< input.len:
    nativeToLE(input[i], output[i])
  output

# nativeToLE : native endian to little endian
# warning : input's endian must be native endian
# mutable parameter version
# slicearray version
template nativeToLE*[T: BigUint, N: static int](input, output: slicearray[N, T]): void {.autoSizeOpt.} =
  unroll(i, 0, N - 1):
    nativeToLE(input[i], output[i])

# nativeToLE : native endian to little endian
# warning : input's endian must be native endian
# return value version
# slicearray version
template nativeToLE*[T: BigUint, N: static int](input: slicearray[N, T]): array[N, T] {.autoSizeOpt.} =
  var output: array[N, T]
  unroll(i, 0, N - 1):
    nativeToLE(input[i], output[i])
  output

# nativeToLE : native endian to little endian
# warning : input's endian must be native endian
# mutable parameter version
# ptr array version
template nativeToLE*[T: BigUint, N: static int](input: ptr array[N, T], output: ptr array[N, T]): void {.autoSizeOpt.} =
  unroll(i, 0, N - 1):
    nativeToLE(input[i], output[i])

# nativeToLE : native endian to little endian
# warning : input's endian must be native endian
# return value version
# ptr array version
template nativeToLE*[T: BigUint, N: static int](input: ptr array[N, T]): array[N, T] {.autoSizeOpt.} =
  var output: array[N, T]
  unroll(i, 0, N - 1):
    nativeToLE(input[i], output[i])
  output

# nativeToLE : native endian to little endian
# warning : input's endian must be little endian
# mutable parameter version
# ptr UncheckedArray version
template nativeToLE*[T: BigUint](input: ptr UncheckedArray[T], output: ptr UncheckedArray[T], length: int): void {.autoSizeOpt.} =
  for i in 0 ..< length:
    nativeToLE(input[i], output[i])

# nativeToLE : native endian to little endian
# warning : input's endian must be little endian
# return value version
# ptr UncheckedArray version
template nativeToLE*[T: BigUint](input: ptr UncheckedArray[T], length: int): seq[T] {.autoSizeOpt.} =
  var output: seq[T] = newSeq[T](length)
  for i in 0 ..< length:
    nativeToLE(input[i], output[i])
  output

# nativeToLE : native endian to little endian
# warning : input's endian must be native endian
# mutable parameter version
# ptr UncheckedArray and static length version
template nativeToLE*[T: BigUint](input: ptr UncheckedArray[T], output: ptr UncheckedArray[T], length: static int): void {.autoSizeOpt.} =
  unroll(i, 0, length - 1):
    nativeToLE(input[i], output[i])

# nativeToLE : native endian to little endian
# warning : input's endian must be native endian
# return value version
# ptr UncheckedArray and static length version
template nativeToLE*[T: BigUint](input: ptr UncheckedArray[T], length: static int): array[length, T] {.autoSizeOpt.} =
  var output: array[length, T]
  unroll(i, 0, length - 1):
    nativeToLE(input[i], output[i])
  output

# decodeLE : uint8 array to big uint array by little endian
# warning : input's endian must be little endian
# input : little endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# mutable parameter version
# array version
template decodeLE*[N1, N2: static int, T: BigUint](input: array[N1, uint8], output: var array[N2, T]): void {.autoSizeOpt.} =
  static:
    doAssert sizeof(uint8) * N1 == sizeof(T) * N2, "The total size of input and output must be same."

  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, N2 - 1):
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl (b * 8))
  else:
    const size: int = N1 * sizeof(uint8)
    copyMem(addr output[0], addr input[0], size)
    when not LE:
      leToNative(output, output)

# decodeLE : uint8 array to big uint array by little endian
# warning : input's endian must be little endian
# input : little endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# return value version
# array version
template decodeLE*[N1, N2: static int, T: BigUint](input: array[N1, uint8]): array[N2, T] {.autoSizeOpt.} =
  static:
    doAssert sizeof(uint8) * N1 == sizeof(T) * N2, "The total size of input and output must be same."
  var output: array[N2, T]
  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, N2 - 1):
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl (b * 8))
  else:
    const size: int = N1 * sizeof(uint8)
    copyMem(addr output[0], addr input[0], size)
    when not LE:
      leToNative(output, output)
  output

# decodeLE : uint8 array to big uint array by little endian
# warning : input's endian must be little endian
# input : little endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# mutable parameter version
# slicearray version
template decodeLE*[N1, N2: static int, T: BigUint](input: slicearray[N1, uint8], output: slicearray[N2, T]): void {.autoSizeOpt.} =
  static:
    doAssert sizeof(uint8) * N1 == sizeof(T) * N2, "The total size of input and output must be same."

  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, N2 - 1):
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl (b * 8))
  else:
    const size: int = N1 * sizeof(uint8)
    copyMem(addr output[0], addr input[0], size)
    when not LE:
      leToNative(output, output)

# decodeLE : uint8 array to big uint array by little endian
# warning : input's endian must be little endian
# input : little endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# return value version
# slicearray version
template decodeLE*[N1, N2: static int, T: BigUint](input: slicearray[N1, uint8]): array[N2, T] {.autoSizeOpt.} =
  static:
    doAssert sizeof(uint8) * N1 == sizeof(T) * N2, "The total size of input and output must be same."
  var output: array[N2, T]
  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, N2 - 1):
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl (b * 8))
  else:
    const size: int = N1 * sizeof(uint8)
    copyMem(addr output[0], addr input[0], size)
    when not LE:
      leToNative(output, output)
  output

# decodeLE : uint8 array to big uint array by little endian
# warning : input's endian must be little endian
# input : little endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# mutable parameter version
# openArray version
template decodeLE*[T: BigUint](input: openArray[uint8], output: var openArray[T]): void {.autoSizeOpt.} =
  when defined(nostd):
    const step: int = sizeof(T)
    for i in 0 ..< output.len:
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl (b * 8))
  else:
    let size: int = input.len * sizeof(uint8)
    copyMem(addr output[0], addr input[0], size)
    when not LE:
      leToNative(output, output)

# decodeLE : uint8 array to big uint array by little endian
# warning : input's endian must be little endian
# input : little endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# return value version
# openArray version
template decodeLE*[T: BigUint](input: openArray[uint8]): seq[T] {.autoSizeOpt.} =
  const step = sizeof(T)
  var output: seq[T] = newSeq[T](input.len div step)
  when defined(nostd):
    for i in 0 ..< output.len:
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl (b * 8))
  else:
    let size: int = input.len * sizeof(uint8)
    copyMem(addr output[0], addr input[0], size)
    when not LE:
      leToNative(output, output)
  output

# decodeLE : uint8 array to big uint array by little endian
# warning : input's endian must be little endian
# input : little endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# mutable parameter version
# openArray and static length version
template decodeLE*[T: BigUint](input: openArray[uint8], output: var openArray[T], outputLen: static int): void {.autoSizeOpt.} =
  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, outputLen - 1):
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl (b * 8))
  else:
    const size: int = outputLen * sizeof(T)
    copyMem(addr output[0], addr input[0], size)
    when not LE:
      leToNative(output, output, outputLen)

# decodeLE : uint8 array to big uint array by little endian
# warning : input's endian must be little endian
# input : little endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# return value version
# openArray and static length version
template decodeLE*[T: BigUint](input: openArray[uint8], outputLen: static int): array[outputLen, T] {.autoSizeOpt.} =
  var output: array[outputLen, T]
  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, outputLen - 1):
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl (b * 8))
  else:
    const size: int = outputLen * sizeof(T)
    copyMem(addr output[0], addr input[0], size)
    when not LE:
      leToNative(output, output, outputLen)
  output

# decodeLE : uint8 array to big uint array by little endian
# warning : input's endian must be little endian
# input : little endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# mutable parameter version
# ptr array version
template decodeLE*[N1, N2: static int, T: BigUint](input: ptr array[N1, uint8], output: ptr array[N2, T]): void {.autoSizeOpt.} =
  static:
    doAssert sizeof(uint8) * N1 == sizeof(T) * N2, "The total size of input and output must be same."

  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, N2 - 1):
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl (b * 8))
  else:
    const size: int = N1 * sizeof(uint8)
    copyMem(addr output[0], addr input[0], size)
    when not LE:
      leToNative(output, output)

# decodeLE : uint8 array to big uint array by little endian
# warning : input's endian must be little endian
# input : little endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# return value version
# ptr array version
template decodeLE*[N1, N2: static int, T: BigUint](input: ptr array[N1, uint8]): array[N2, T] {.autoSizeOpt.} =
  static:
    doAssert sizeof(uint8) * N1 == sizeof(T) * N2, "The total size of input and output must be same."
  var output: array[N2, T]
  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, N2 - 1):
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl (b * 8))
  else:
    const size: int = N1 * sizeof(uint8)
    copyMem(addr output[0], addr input[0], size)
    when not LE:
      leToNative(output, output)
  output

# decodeLE : uint8 array to big uint array by little endian
# warning : input's endian must be little endian
# input : little endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# mutable parameter version
# ptr UncheckedArray version
template decodeLE*[T: BigUint](input: ptr UncheckedArray[uint8], output: ptr UncheckedArray[T], outputLen: int): void {.autoSizeOpt.} =
  when defined(nostd):
    const step: int = sizeof(T)
    for i in 0 ..< outputLen:
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl (b * 8))
  else:
    let size: int = outputLen * sizeof(T)
    copyMem(addr output[0], addr input[0], size)
    when not LE:
      leToNative(output, output, outputLen)

# decodeLE : uint8 array to big uint array by little endian
# warning : input's endian must be little endian
# input : little endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# return value version
# ptr UncheckedArray version
template decodeLE*[T: BigUint](input: ptr UncheckedArray[uint8], outputLen: int): seq[T] {.autoSizeOpt.} =
  var output: seq[T] = newSeq[T](outputLen)
  when defined(nostd):
    const step: int = sizeof(T)
    for i in 0 ..< outputLen:
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl (b * 8))
  else:
    let size: int = outputLen * sizeof(T)
    copyMem(addr output[0], addr input[0], size)
    when not LE:
      leToNative(output, output, outputLen)
  output

# decodeLE : uint8 array to big uint array by little endian
# warning : input's endian must be little endian
# input : little endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# mutable parameter version
# ptr UncheckedArray and static length version
template decodeLE*[T: BigUint](input: ptr UncheckedArray[uint8], output: ptr UncheckedArray[T], outputLen: static int): void {.autoSizeOpt.} =
  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, outputLen - 1):
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl (b * 8))
  else:
    const size: int = outputLen * sizeof(T)
    copyMem(addr output[0], addr input[0], size)
    when not LE:
      leToNative(output, output, outputLen)

# decodeLE : uint8 array to big uint array by little endian
# warning : input's endian must be little endian
# input : little endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# return value version
# ptr UncheckedArray and static length version
template decodeLE*[T: BigUint](input: ptr UncheckedArray[uint8], outputLen: static int): array[outputLen, T] {.autoSizeOpt.} =
  var output: array[outputLen, T]
  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, outputLen - 1):
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl (b * 8))
  else:
    const size: int = outputLen * sizeof(T)
    copyMem(addr output[0], addr input[0], size)
    when not LE:
      leToNative(output, output, outputLen)
  output

# decodeBE : uint8 array to big uint array by big endian
# warning : input's endian must be big endian
# input : big endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# mutable parameter version
# array version
template decodeBE*[N1, N2: static int, T: BigUint](input: array[N1, uint8], output: var array[N2, T]): void {.autoSizeOpt.} =
  static:
    doAssert sizeof(uint8) * N1 == sizeof(T) * N2, "The total size of input and output must be same."

  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, N2 - 1):
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl ((step - 1 - b) * 8))
  else:
    const size: int = N1 * sizeof(uint8)
    copyMem(addr output[0], addr input[0], size)
    when not BE:
      beToNative(output, output)

# decodeBE : uint8 array to big uint array by big endian
# warning : input's endian must be big endian
# input : big endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# return value version
# array version
template decodeBE*[N1, N2: static int, T: BigUint](input: array[N1, uint8]): array[N2, T] {.autoSizeOpt.} =
  static:
    doAssert sizeof(uint8) * N1 == sizeof(T) * N2, "The total size of input and output must be same."
  var output: array[N2, T]
  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, N2 - 1):
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl ((step - 1 - b) * 8))
  else:
    const size: int = N1 * sizeof(uint8)
    copyMem(addr output[0], addr input[0], size)
    when not BE:
      beToNative(output, output)
  output

# decodeBE : uint8 array to big uint array by big endian
# warning : input's endian must be big endian
# input : big endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# mutable parameter version
# slicearray version
template decodeBE*[N1, N2: static int, T: BigUint](input: slicearray[N1, uint8], output: slicearray[N2, T]): void {.autoSizeOpt.} =
  static:
    doAssert sizeof(uint8) * N1 == sizeof(T) * N2, "The total size of input and output must be same."

  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, N2 - 1):
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl ((step - 1 - b) * 8))
  else:
    const size: int = N1 * sizeof(uint8)
    copyMem(addr output[0], addr input[0], size)
    when not BE:
      beToNative(output, output)

# decodeBE : uint8 array to big uint array by big endian
# warning : input's endian must be big endian
# input : big endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# return value version
# slicearray version
template decodeBE*[N1, N2: static int, T: BigUint](input: slicearray[N1, uint8]): array[N2, T] {.autoSizeOpt.} =
  static:
    doAssert sizeof(uint8) * N1 == sizeof(T) * N2, "The total size of input and output must be same."
  var output: array[N2, T]
  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, N2 - 1):
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl ((step - 1 - b) * 8))
  else:
    const size: int = N1 * sizeof(uint8)
    copyMem(addr output[0], addr input[0], size)
    when not BE:
      beToNative(output, output)
  output

# decodeBE : uint8 array to big uint array by big endian
# warning : input's endian must be big endian
# input : big endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# mutable parameter version
# openArray version
template decodeBE*[T: BigUint](input: openArray[uint8], output: var openArray[T]): void {.autoSizeOpt.} =
  when defined(nostd):
    const step: int = sizeof(T)
    for i in 0 ..< output.len:
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl ((step - 1 - b) * 8))
  else:
    let size: int = input.len * sizeof(uint8)
    copyMem(addr output[0], addr input[0], size)
    when not BE:
      beToNative(output, output)

# decodeBE : uint8 array to big uint array by big endian
# warning : input's endian must be big endian
# input : big endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# return value version
# openArray version
template decodeBE*[T: BigUint](input: openArray[uint8]): seq[T] {.autoSizeOpt.} =
  const step = sizeof(T)
  var output: seq[T] = newSeq[T](input.len div step)
  when defined(nostd):
    for i in 0 ..< output.len:
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl ((step - 1 - b) * 8))
  else:
    let size: int = input.len * sizeof(uint8)
    copyMem(addr output[0], addr input[0], size)
    when not BE:
      beToNative(output, output)
  output

# decodeBE : uint8 array to big uint array by big endian
# warning : input's endian must be big endian
# input : big endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# mutable parameter version
# openArray and static length version
template decodeBE*[T: BigUint](input: openArray[uint8], output: var openArray[T], outputLen: static int): void {.autoSizeOpt.} =
  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, outputLen - 1):
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl ((step - 1 - b) * 8))
  else:
    const size: int = outputLen * sizeof(T)
    copyMem(addr output[0], addr input[0], size)
    when not BE:
      beToNative(output, output, outputLen)

# decodeBE : uint8 array to big uint array by big endian
# warning : input's endian must be big endian
# input : big endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# return value version
# openArray and static length version
template decodeBE*[T: BigUint](input: openArray[uint8], outputLen: static int): array[outputLen, T] {.autoSizeOpt.} =
  var output: array[outputLen, T]
  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, outputLen - 1):
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl ((step - 1 - b) * 8))
  else:
    const size: int = outputLen * sizeof(T)
    copyMem(addr output[0], addr input[0], size)
    when not BE:
      beToNative(output, output, outputLen)
  output

# decodeBE : uint8 array to big uint array by big endian
# warning : input's endian must be big endian
# input : big endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# mutable parameter version
# ptr array version
template decodeBE*[N1, N2: static int, T: BigUint](input: ptr array[N1, uint8], output: ptr array[N2, T]): void {.autoSizeOpt.} =
  static:
    doAssert sizeof(uint8) * N1 == sizeof(T) * N2, "The total size of input and output must be same."

  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, N2 - 1):
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl ((step - 1 - b) * 8))
  else:
    const size: int = N1 * sizeof(uint8)
    copyMem(addr output[0], addr input[0], size)
    when not BE:
      beToNative(output, output)

# decodeBE : uint8 array to big uint array by big endian
# warning : input's endian must be big endian
# input : big endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# return value version
# ptr array version
template decodeBE*[N1, N2: static int, T: BigUint](input: ptr array[N1, uint8]): array[N2, T] {.autoSizeOpt.} =
  static:
    doAssert sizeof(uint8) * N1 == sizeof(T) * N2, "The total size of input and output must be same."
  var output: array[N2, T]
  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, N2 - 1):
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl ((step - 1 - b) * 8))
  else:
    const size: int = N1 * sizeof(uint8)
    copyMem(addr output[0], addr input[0], size)
    when not BE:
      beToNative(output, output)
  output

# decodeBE : uint8 array to big uint array by big endian
# warning : input's endian must be big endian
# input : big endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# mutable parameter version
# ptr UncheckedArray version
template decodeBE*[T: BigUint](input: ptr UncheckedArray[uint8], output: ptr UncheckedArray[T], outputLen: int): void {.autoSizeOpt.} =
  when defined(nostd):
    const step: int = sizeof(T)
    for i in 0 ..< outputLen:
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl ((step - 1 - b) * 8))
  else:
    let size: int = outputLen * sizeof(T)
    copyMem(addr output[0], addr input[0], size)
    when not BE:
      beToNative(output, output, outputLen)

# decodeBE : uint8 array to big uint array by big endian
# warning : input's endian must be big endian
# input : big endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# return value version
# ptr UncheckedArray version
template decodeBE*[T: BigUint](input: ptr UncheckedArray[uint8], outputLen: int): seq[T] {.autoSizeOpt.} =
  var output: seq[T] = newSeq[T](outputLen)
  when defined(nostd):
    const step: int = sizeof(T)
    for i in 0 ..< outputLen:
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl ((step - 1 - b) * 8))
  else:
    let size: int = outputLen * sizeof(T)
    copyMem(addr output[0], addr input[0], size)
    when not BE:
      beToNative(output, output, outputLen)
  output

# decodeBE : uint8 array to big uint array by big endian
# warning : input's endian must be big endian
# input : big endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# mutable parameter version
# ptr UncheckedArray and static length version
template decodeBE*[T: BigUint](input: ptr UncheckedArray[uint8], output: ptr UncheckedArray[T], outputLen: static int): void {.autoSizeOpt.} =
  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, outputLen - 1):
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl ((step - 1 - b) * 8))
  else:
    const size: int = outputLen * sizeof(T)
    copyMem(addr output[0], addr input[0], size)
    when not BE:
      beToNative(output, output, outputLen)

# decodeBE : uint8 array to big uint array by big endian
# warning : input's endian must be big endian
# input : big endian uint8 array
# output : cpu native endian uint16/uint32/uint64 array
# return value version
# ptr UncheckedArray and static length version
template decodeBE*[T: BigUint](input: ptr UncheckedArray[uint8], outputLen: static int): array[outputLen, T] {.autoSizeOpt.} =
  var output: array[outputLen, T]
  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, outputLen - 1):
      output[i] = 0
      unroll(b, 0, step - 1):
        output[i] = output[i] or (input[i * step + b].T shl ((step - 1 - b) * 8))
  else:
    const size: int = outputLen * sizeof(T)
    copyMem(addr output[0], addr input[0], size)
    when not BE:
      beToNative(output, output, outputLen)
  output

# encodeLE : big uint array to uint8 array by little endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : little endian uint8 array
# mutable parameter version
# array version
template encodeLE*[N1, N2: static int, T: BigUint](input: array[N1, T], output: var array[N2, uint8]): void {.autoSizeOpt.} =
  static:
    doAssert sizeof(T) * N1 == sizeof(uint8) * N2, "The total size of input and output must be same."

  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, N1 - 1):
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr (b * 8)) and 0xFF)
  else:
    const size: int = N2 * sizeof(uint8)
    when LE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToLE(addr input[0], cast[ptr array[N1, T]](addr output[0]))

# encodeLE : big uint array to uint8 array by little endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : little endian uint8 array
# return value version
# array version
template encodeLE*[N1, N2: static int, T: BigUint](input: array[N1, T]): array[N2, uint8] {.autoSizeOpt.} =
  static:
    doAssert sizeof(T) * N1 == sizeof(uint8) * N2, "The total size of input and output must be same."
  var output: array[N2, uint8]
  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, N1 - 1):
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr (b * 8)) and 0xFF)
  else:
    const size: int = N2 * sizeof(uint8)
    when LE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToLE(addr input[0], cast[ptr array[N1, T]](addr output[0]))
  output

# encodeLE : big uint array to uint8 array by little endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : little endian uint8 array
# mutable parameter version
# slicearray version
template encodeLE*[N1, N2: static int, T: BigUint](input: slicearray[N1, T], output: slicearray[N2, uint8]): void {.autoSizeOpt.} =
  static:
    doAssert sizeof(T) * N1 == sizeof(uint8) * N2, "The total size of input and output must be same."

  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, N1 - 1):
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr (b * 8)) and 0xFF)
  else:
    const size: int = N2 * sizeof(uint8)
    when LE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToLE(input, output.castTo(T))

# encodeLE : big uint array to uint8 array by little endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : little endian uint8 array
# return value version
# slicearray version
template encodeLE*[N1, N2: static int, T: BigUint](input: slicearray[N1, T]): array[N2, uint8] {.autoSizeOpt.} =
  static:
    doAssert sizeof(T) * N1 == sizeof(uint8) * N2, "The total size of input and output must be same."
  var output: array[N2, uint8]
  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, N1 - 1):
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr (b * 8)) and 0xFF)
  else:
    const size: int = N2 * sizeof(uint8)
    when LE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToLE(addr input[0], cast[ptr array[N1, T]](addr output[0]))
  output

# encodeLE : big uint array to uint8 array by little endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : little endian uint8 array
# mutable parameter version
# openArray version
template encodeLE*[T: BigUint](input: openArray[T], output: var openArray[uint8]): void {.autoSizeOpt.} =
  when defined(nostd):
    const step: int = sizeof(T)
    for i in 0 ..< input.len:
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr (b * 8)) and 0xFF)
  else:
    let size: int = input.len * sizeof(T)
    when LE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToLE(cast[ptr UncheckedArray[T]](addr input[0]), cast[ptr UncheckedArray[T]](addr output[0]), input.len)

# encodeLE : big uint array to uint8 array by little endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : little endian uint8 array
# return value version
# openArray version
template encodeLE*[T: BigUint](input: openArray[T]): seq[uint8] {.autoSizeOpt.} =
  const step = sizeof(T)
  var output: seq[uint8] = newSeq[uint8](input.len * step)
  when defined(nostd):
    for i in 0 ..< input.len:
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr (b * 8)) and 0xFF)
  else:
    let size: int = input.len * step
    when LE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToLE(cast[ptr UncheckedArray[T]](addr input[0]), cast[ptr UncheckedArray[T]](addr output[0]), input.len)
  output

# encodeLE : big uint array to uint8 array by little endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : little endian uint8 array
# mutable parameter version
# openArray and static length version
template encodeLE*[T: BigUint](input: openArray[T], output: var openArray[uint8], inputLen: static int): void {.autoSizeOpt.} =
  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, inputLen - 1):
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr (b * 8)) and 0xFF)
  else:
    const size: int = inputLen * sizeof(T)
    when LE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToLE(cast[ptr UncheckedArray[T]](addr input[0]), cast[ptr UncheckedArray[T]](addr output[0]), inputLen)

# encodeLE : big uint array to uint8 array by little endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : little endian uint8 array
# return value version
# openArray and static length version
template encodeLE*[T: BigUint](input: openArray[T], inputLen: static int): array[inputLen * sizeof(T), uint8] {.autoSizeOpt.} =
  var output: array[inputLen * sizeof(T), uint8]
  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, inputLen - 1):
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr (b * 8)) and 0xFF)
  else:
    const size: int = inputLen * sizeof(T)
    when LE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToLE(cast[ptr UncheckedArray[T]](addr input[0]), cast[ptr UncheckedArray[T]](addr output[0]), inputLen)
  output

# encodeLE : big uint array to uint8 array by little endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : little endian uint8 array
# mutable parameter version
# ptr array version
template encodeLE*[N1, N2: static int, T](input: ptr array[N1, T], output: ptr array[N2, uint8]): void {.autoSizeOpt.} =
  static:
    doAssert sizeof(T) * N1 == sizeof(uint8) * N2, "The total size of input and output must be same."

  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, N1 - 1):
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr (b * 8)) and 0xFF)
  else:
    const size: int = N2 * sizeof(uint8)
    when LE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToLE(input, cast[ptr array[N1, T]](addr output[0]))

# encodeLE : big uint array to uint8 array by little endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : little endian uint8 array
# return value version
# ptr array version
template encodeLE*[N1, N2: static int, T](input: ptr array[N1, T]): array[N2, uint8] {.autoSizeOpt.} =
  static:
    doAssert sizeof(T) * N1 == sizeof(uint8) * N2, "The total size of input and output must be same."
  var output: array[N2, uint8]
  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, N1 - 1):
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr (b * 8)) and 0xFF)
  else:
    const size: int = N2 * sizeof(uint8)
    when LE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToLE(input, cast[ptr array[N1, T]](addr output[0]))
  output

# encodeLE : big uint array to uint8 array by little endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : little endian uint8 array
# mutable parameter version
# ptr UncheckedArray version
template encodeLE*[T](input: ptr UncheckedArray[T], output: ptr UncheckedArray[uint8], inputLen: int): void {.autoSizeOpt.} =
  when defined(nostd):
    const step: int = sizeof(T)
    for i in 0 ..< inputLen:
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr (b * 8)) and 0xFF)
  else:
    let size: int = inputLen * sizeof(T)
    when LE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToLE(input, cast[ptr UncheckedArray[T]](addr output[0]), inputLen)

# encodeLE : big uint array to uint8 array by little endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : little endian uint8 array
# return value version
# ptr UncheckedArray version
template encodeLE*[T](input: ptr UncheckedArray[T], inputLen: int): seq[uint8] {.autoSizeOpt.} =
  const step = sizeof(T)
  var output: seq[uint8] = newSeq[uint8](inputLen * step)
  when defined(nostd):
    for i in 0 ..< inputLen:
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr (b * 8)) and 0xFF)
  else:
    let size: int = inputLen * step
    when LE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToLE(input, cast[ptr UncheckedArray[T]](addr output[0]), inputLen)
  output

# encodeLE : big uint array to uint8 array by little endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : little endian uint8 array
# mutable parameter version
# ptr UncheckedArray and static length version
template encodeLE*[T](input: ptr UncheckedArray[T], output: ptr UncheckedArray[uint8], inputLen: static int): void {.autoSizeOpt.} =
  const step: int = sizeof(T)

  when defined(nostd):
    unroll(i, 0, inputLen - 1):
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr (b * 8)) and 0xFF)
  else:
    const size: int = inputLen * sizeof(T)
    when LE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToLE(input, cast[ptr UncheckedArray[T]](addr output[0]), inputLen)

# encodeLE : big uint array to uint8 array by little endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : little endian uint8 array
# return value version
# ptr UncheckedArray and static length version
template encodeLE*[T](input: ptr UncheckedArray[T], inputLen: static int): array[inputLen * sizeof(T), uint8] {.autoSizeOpt.} =
  const step = sizeof(T)
  var output: array[inputLen * step, uint8]
  when defined(nostd):
    unroll(i, 0, inputLen - 1):
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr (b * 8)) and 0xFF)
  else:
    const size: int = inputLen * step
    when LE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToLE(input, cast[ptr UncheckedArray[T]](addr output[0]), inputLen)
  output

# encodeBE : big uint array to uint8 array by big endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : big endian uint8 array
# mutable parameter version
# array version
template encodeBE*[N1, N2: static int, T: BigUint](input: array[N1, T], output: var array[N2, uint8]): void {.autoSizeOpt.} =
  static:
    doAssert sizeof(T) * N1 == sizeof(uint8) * N2, "The total size of input and output must be same."

  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, N1 - 1):
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr ((step - b - 1) * 8)) and 0xFF)
  else:
    const size: int = N2 * sizeof(uint8)
    when BE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToBE(addr input, cast[ptr array[N1, T]](addr output[0]))

# encodeBE : big uint array to uint8 array by big endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : big endian uint8 array
# return value version
# array version
template encodeBE*[N1, N2: static int, T: BigUint](input: array[N1, T]): array[N2, uint8] {.autoSizeOpt.} =
  static:
    doAssert sizeof(T) * N1 == sizeof(uint8) * N2, "The total size of input and output must be same."
  var output: array[N2, uint8]
  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, N1 - 1):
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr ((step - b - 1) * 8)) and 0xFF)
  else:
    const size: int = N2 * sizeof(uint8)
    when BE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToBE(addr input[0], cast[ptr array[N1, T]](addr output[0]))
  output

# encodeBE : big uint array to uint8 array by big endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : big endian uint8 array
# mutable parameter version
# slicearray version
template encodeBE*[N1, N2: static int, T: BigUint](input: slicearray[N1, T], output: slicearray[N2, uint8]): void {.autoSizeOpt.} =
  static:
    doAssert sizeof(T) * N1 == sizeof(uint8) * N2, "The total size of input and output must be same."

  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, N1 - 1):
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr ((step - b - 1) * 8)) and 0xFF)
  else:
    const size: int = N2 * sizeof(uint8)
    when BE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToBE(input, output.castTo(T))

# encodeBE : big uint array to uint8 array by big endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : big endian uint8 array
# return value version
# slicearray version
template encodeBE*[N1, N2: static int, T: BigUint](input: slicearray[N1, T]): array[N2, uint8] {.autoSizeOpt.} =
  static:
    doAssert sizeof(T) * N1 == sizeof(uint8) * N2, "The total size of input and output must be same."
  var output: array[N2, uint8]
  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, N1 - 1):
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr ((step - b - 1) * 8)) and 0xFF)
  else:
    const size: int = N2 * sizeof(uint8)
    when BE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToBE(addr input[0], cast[ptr array[N1, T]](addr output[0]))
  output

# encodeBE : big uint array to uint8 array by big endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : big endian uint8 array
# mutable parameter version
# openArray version
template encodeBE*[T: BigUint](input: openArray[T], output: var openArray[uint8]): void {.autoSizeOpt.} =
  when defined(nostd):
    const step: int = sizeof(T)
    for i in 0 ..< input.len:
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr ((step - b - 1) * 8)) and 0xFF)
  else:
    let size: int = input.len * sizeof(T)
    when BE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToBE(cast[ptr UncheckedArray[T]](addr input[0]), cast[ptr UncheckedArray[T]](addr output[0]), input.len)

# encodeBE : big uint array to uint8 array by big endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : big endian uint8 array
# return value version
# openArray version
template encodeBE*[T: BigUint](input: openArray[T]): seq[uint8] {.autoSizeOpt.} =
  const step = sizeof(T)
  var output: seq[uint8] = newSeq[uint8](input.len * step)
  when defined(nostd):
    for i in 0 ..< input.len:
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr ((step - b - 1) * 8)) and 0xFF)
  else:
    let size: int = input.len * step
    when BE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToBE(cast[ptr UncheckedArray[T]](addr input[0]), cast[ptr UncheckedArray[T]](addr output[0]), input.len)
  output

# encodeBE : big uint array to uint8 array by big endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : big endian uint8 array
# mutable parameter version
# openArray and static length version
template encodeBE*[T: BigUint](input: openArray[T], output: var openArray[uint8], inputLen: static int): void {.autoSizeOpt.} =
  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, inputLen - 1):
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr ((step - b - 1) * 8)) and 0xFF)
  else:
    const size: int = inputLen * sizeof(T)
    when BE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToBE(cast[ptr UncheckedArray[T]](addr input[0]), cast[ptr UncheckedArray[T]](addr output[0]), inputLen)

# encodeBE : big uint array to uint8 array by big endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : big endian uint8 array
# return value version
# openArray and static length version
template encodeBE*[T: BigUint](input: openArray[T], inputLen: static int): array[inputLen * sizeof(T), uint8] {.autoSizeOpt.} =
  var output: array[inputLen * sizeof(T), uint8]
  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, inputLen - 1):
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr ((step - b - 1) * 8)) and 0xFF)
  else:
    const size: int = inputLen * sizeof(T)
    when BE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToBE(cast[ptr UncheckedArray[T]](addr input[0]), cast[ptr UncheckedArray[T]](addr output[0]), inputLen)
  output

# encodeBE : big uint array to uint8 array by big endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : big endian uint8 array
# mutable parameter version
# ptr array version
template encodeBE*[N1, N2: static int, T](input: ptr array[N1, T], output: ptr array[N2, uint8]): void {.autoSizeOpt.} =
  static:
    doAssert sizeof(T) * N1 == sizeof(uint8) * N2, "The total size of input and output must be same."

  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, N1 - 1):
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr ((step - b - 1) * 8)) and 0xFF)
  else:
    const size: int = N2 * sizeof(uint8)
    when BE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToBE(input, cast[ptr array[N1, T]](addr output[0]))

# encodeBE : big uint array to uint8 array by big endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : big endian uint8 array
# return value version
# ptr array version
template encodeBE*[N1, N2: static int, T](input: ptr array[N1, T]): array[N2, uint8] {.autoSizeOpt.} =
  static:
    doAssert sizeof(T) * N1 == sizeof(uint8) * N2, "The total size of input and output must be same."
  var output: array[N2, uint8]
  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, N1 - 1):
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr ((step - b - 1) * 8)) and 0xFF)
  else:
    const size: int = N2 * sizeof(uint8)
    when BE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToBE(input, cast[ptr array[N1, T]](addr output[0]))
  output

# encodeBE : big uint array to uint8 array by big endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : big endian uint8 array
# mutable parameter version
# ptr UncheckedArray version
template encodeBE*[T](input: ptr UncheckedArray[T], output: ptr UncheckedArray[uint8], inputLen: int): void {.autoSizeOpt.} =
  when defined(nostd):
    const step: int = sizeof(T)
    for i in 0 ..< inputLen:
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr ((step - b - 1) * 8)) and 0xFF)
  else:
    let size: int = inputLen * sizeof(T)
    when BE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToBE(input, cast[ptr UncheckedArray[T]](addr output[0]), inputLen)

# encodeBE : big uint array to uint8 array by big endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : big endian uint8 array
# return value version
# ptr UncheckedArray version
template encodeBE*[T](input: ptr UncheckedArray[T], inputLen: int): seq[uint8] {.autoSizeOpt.} =
  const step = sizeof(T)
  var output: seq[uint8] = newSeq[uint8](inputLen * step)
  when defined(nostd):
    for i in 0 ..< inputLen:
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr ((step - b - 1) * 8)) and 0xFF)
  else:
    let size: int = inputLen * step
    when BE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToBE(input, cast[ptr UncheckedArray[T]](addr output[0]), inputLen)
  output

# encodeBE : big uint array to uint8 array by big endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : big endian uint8 array
# mutable parameter version
# ptr UncheckedArray and static length version
template encodeBE*[T](input: ptr UncheckedArray[T], output: ptr UncheckedArray[uint8], inputLen: static int): void {.autoSizeOpt.} =
  when defined(nostd):
    const step: int = sizeof(T)
    unroll(i, 0, inputLen - 1):
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr ((step - b - 1) * 8)) and 0xFF)
  else:
    const size: int = inputLen * sizeof(T)
    when BE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToBE(input, cast[ptr UncheckedArray[T]](addr output[0]), inputLen)

# encodeBE : big uint array to uint8 array by big endian
# warning : input's endian must be native endian
# input : cpu native endian uint16/uint32/uint64 array
# output : big endian uint8 array
# return value version
# ptr UncheckedArray and static length version
template encodeBE*[T](input: ptr UncheckedArray[T], inputLen: static int): array[inputLen * sizeof(T), uint8] {.autoSizeOpt.} =
  const step = sizeof(T)
  var output: array[inputLen * step, uint8]
  when defined(nostd):
    unroll(i, 0, inputLen - 1):
      unroll(b, 0, step - 1):
        output[i * step + b] = uint8((input[i] shr ((step - b - 1) * 8)) and 0xFF)
  else:
    const size: int = inputLen * step
    when BE:
      copyMem(addr output[0], addr input[0], size)
    else:
      nativeToBE(input, cast[ptr UncheckedArray[T]](addr output[0]), inputLen)
  output

# fromBytesLE : uint8 array to big uint
# warning : input's endian must be little endian
# input : little endian uint8 array
# output : cpu native endian uint16/uint32/uint64
# mutable parameter version
# array version
template fromBytesLE*[T: BigUint, N: static int](input: array[N, uint8], output: var T): void {.autoSizeOpt.} =
  static:
    doAssert N == sizeof(T), "The total size of input and output must be same."

  when defined(nostd):
    output = 0
    unroll(b, 0, sizeof(T) - 1):
      output = output or (input[b].T shl (b * 8))
  else:
    const size: int = sizeof(T)
    copyMem(addr output, addr input[0], size)
    when not LE:
      leToNative(output, output)

# fromBytesLE : uint8 array to big uint
# warning : input's endian must be little endian
# input : little endian uint8 array
# output : cpu native endian uint16/uint32/uint64
# return value version
# array version
template fromBytesLE*[T: BigUint, N: static int](input: array[N, uint8]): T {.autoSizeOpt.} =
  static:
    doAssert N == sizeof(T), "The total size of input and output must be same."
  var output: T
  when defined(nostd):
    output = 0
    unroll(b, 0, sizeof(T) - 1):
      output = output or (input[b].T shl (b * 8))
  else:
    const size: int = sizeof(T)
    copyMem(addr output, addr input[0], size)
    when not LE:
      leToNative(output, output)
  output

# fromBytesLE : uint8 array to big uint
# warning : input's endian must be little endian
# input : little endian uint8 array
# output : cpu native endian uint16/uint32/uint64
# mutable parameter version
# slicearray version
template fromBytesLE*[T: BigUint, N: static int](input: slicearray[N, uint8], output: var T): void {.autoSizeOpt.} =
  static:
    doAssert N == sizeof(T), "The total size of input and output must be same."

  when defined(nostd):
    output = 0
    unroll(b, 0, sizeof(T) - 1):
      output = output or (input[b].T shl (b * 8))
  else:
    const size: int = sizeof(T)
    copyMem(addr output, addr input[0], size)
    when not LE:
      leToNative(output, output)

# fromBytesLE : uint8 array to big uint
# warning : input's endian must be little endian
# input : little endian uint8 array
# output : cpu native endian uint16/uint32/uint64
# return value version
# slicearray version
template fromBytesLE*[T: BigUint, N: static int](input: slicearray[N, uint8]): T {.autoSizeOpt.} =
  static:
    doAssert N == sizeof(T), "The total size of input and output must be same."
  var output: T
  when defined(nostd):
    output = 0
    unroll(b, 0, sizeof(T) - 1):
      output = output or (input[b].T shl (b * 8))
  else:
    const size: int = sizeof(T)
    copyMem(addr output, addr input[0], size)
    when not LE:
      leToNative(output, output)
  output

# fromBytesLE : uint8 array to big uint
# warning : input's endian must be little endian
# input : little endian uint8 array
# output : cpu native endian uint16/uint32/uint64
# mutable parameter version
# openArray version
template fromBytesLE*[T: BigUint](input: openArray[uint8], output: var T): void {.autoSizeOpt.} =
  when defined(nostd):
    output = 0
    unroll(b, 0, sizeof(T) - 1):
      output = output or (input[b].T shl (b * 8))
  else:
    const size: int = sizeof(T)
    copyMem(addr output, addr input[0], size)
    when not LE:
      leToNative(output, output)

# fromBytesLE : uint8 array to big uint
# warning : input's endian must be little endian
# input : little endian uint8 array
# output : cpu native endian uint16/uint32/uint64
# return value version
# openArray version
template fromBytesLE*[T: BigUint](input: openArray[uint8]): T {.autoSizeOpt.} =
  var output: T
  when defined(nostd):
    output = 0
    unroll(b, 0, sizeof(T) - 1):
      output = output or (input[b].T shl (b * 8))
  else:
    const size: int = sizeof(T)
    copyMem(addr output, addr input[0], size)
    when not LE:
      leToNative(output, output)
  output

# fromBytesLE : uint8 array to big uint
# warning : input's endian must be little endian
# input : little endian uint8 array
# output : cpu native endian uint16/uint32/uint64
# mutable parameter version
# ptr array version
template fromBytesLE*[T: BigUint, N: static int](input: ptr array[N, uint8], output: ptr T): void {.autoSizeOpt.} =
  static:
    doAssert N == sizeof(T), "The total size of input and output must be same."

  when defined(nostd):
    output[] = 0
    unroll(b, 0, sizeof(T) - 1):
      output[] = output[] or (input[b].T shl (b * 8))
  else:
    const size: int = sizeof(T)
    copyMem(output, input, size)
    when not LE:
      leToNative(output, output)

# fromBytesLE : uint8 array to big uint
# warning : input's endian must be little endian
# input : little endian uint8 array
# output : cpu native endian uint16/uint32/uint64
# return value version
# ptr array version
template fromBytesLE*[T: BigUint, N: static int](input: ptr array[N, uint8]): T {.autoSizeOpt.} =
  static:
    doAssert N == sizeof(T), "The total size of input and output must be same."
  var output: T
  when defined(nostd):
    output = 0
    unroll(b, 0, sizeof(T) - 1):
      output = output or (input[b].T shl (b * 8))
  else:
    const size: int = sizeof(T)
    copyMem(addr output, input, size)
    when not LE:
      leToNative(output, output)
  output

# fromBytesLE : uint8 array to big uint
# warning : input's endian must be little endian
# input : little endian uint8 array
# output : cpu native endian uint16/uint32/uint64
# mutable parameter version
# ptr UncheckedArray version
template fromBytesLE*[T: BigUint](input: ptr UncheckedArray[uint8], output: ptr T): void {.autoSizeOpt.} =
  when defined(nostd):
    output[] = 0
    unroll(b, 0, sizeof(T) - 1):
      output[] = output[] or (input[b].T shl (b * 8))
  else:
    const size: int = sizeof(T)
    copyMem(output, input, size)
    when not LE:
      leToNative(output, output)

# fromBytesLE : uint8 array to big uint
# warning : input's endian must be little endian
# input : little endian uint8 array
# output : cpu native endian uint16/uint32/uint64
# return value version
# ptr UncheckedArray version
template fromBytesLE*[T: BigUint](input: ptr UncheckedArray[uint8]): T {.autoSizeOpt.} =
  var output: T
  when defined(nostd):
    output = 0
    unroll(b, 0, sizeof(T) - 1):
      output = output or (input[b].T shl (b * 8))
  else:
    const size: int = sizeof(T)
    copyMem(addr output, input, size)
    when not LE:
      leToNative(output, output)
  output

# fromBytesBE : uint8 array to big uint by big endian
# warning : input's endian must be big endian
# input : big endian uint8 array
# output : cpu native endian uint16/uint32/uint64
# mutable parameter version
# array version
template fromBytesBE*[T: BigUint, N: static int](input: array[N, uint8], output: var T): void {.autoSizeOpt.} =
  static:
    doAssert N == sizeof(T), "The total size of input and output must be same."

  when defined(nostd):
    output = 0
    unroll(b, 0, sizeof(T) - 1):
      output = output or (input[b].T shl ((sizeof(T) - 1 - b) * 8))
  else:
    const size: int = sizeof(T)
    copyMem(addr output, addr input[0], size)
    when not BE:
      beToNative(output, output)

# fromBytesBE : uint8 array to big uint by big endian
# warning : input's endian must be big endian
# input : big endian uint8 array
# output : cpu native endian uint16/uint32/uint64
# return value version
# array version
template fromBytesBE*[T: BigUint, N: static int](input: array[N, uint8]): T {.autoSizeOpt.} =
  static:
    doAssert N == sizeof(T), "The total size of input and output must be same."
  var output: T
  when defined(nostd):
    output = 0
    unroll(b, 0, sizeof(T) - 1):
      output = output or (input[b].T shl ((sizeof(T) - 1 - b) * 8))
  else:
    const size: int = sizeof(T)
    copyMem(addr output, addr input[0], size)
    when not BE:
      beToNative(output, output)
  output

# fromBytesBE : uint8 array to big uint by big endian
# warning : input's endian must be big endian
# input : big endian uint8 array
# output : cpu native endian uint16/uint32/uint64
# mutable parameter version
# slicearray version
template fromBytesBE*[T: BigUint, N: static int](input: slicearray[N, uint8], output: var T): void {.autoSizeOpt.} =
  static:
    doAssert N == sizeof(T), "The total size of input and output must be same."

  when defined(nostd):
    output = 0
    unroll(b, 0, sizeof(T) - 1):
      output = output or (input[b].T shl ((sizeof(T) - 1 - b) * 8))
  else:
    const size: int = sizeof(T)
    copyMem(addr output, addr input[0], size)
    when not BE:
      beToNative(output, output)

# fromBytesBE : uint8 array to big uint by big endian
# warning : input's endian must be big endian
# input : big endian uint8 array
# output : cpu native endian uint16/uint32/uint64
# return value version
# slicearray version
template fromBytesBE*[T: BigUint, N: static int](input: slicearray[N, uint8]): T {.autoSizeOpt.} =
  static:
    doAssert N == sizeof(T), "The total size of input and output must be same."
  var output: T
  when defined(nostd):
    output = 0
    unroll(b, 0, sizeof(T) - 1):
      output = output or (input[b].T shl ((sizeof(T) - 1 - b) * 8))
  else:
    const size: int = sizeof(T)
    copyMem(addr output, addr input[0], size)
    when not BE:
      beToNative(output, output)
  output

# fromBytesBE : uint8 array to big uint by big endian
# warning : input's endian must be big endian
# input : big endian uint8 array
# output : cpu native endian uint16/uint32/uint64
# mutable parameter version
# openArray version
template fromBytesBE*[T: BigUint](input: openArray[uint8], output: var T): void {.autoSizeOpt.} =
  when defined(nostd):
    output = 0
    unroll(b, 0, sizeof(T) - 1):
      output = output or (input[b].T shl ((sizeof(T) - 1 - b) * 8))
  else:
    const size: int = sizeof(T)
    copyMem(addr output, addr input[0], size)
    when not BE:
      beToNative(output, output)

# fromBytesBE : uint8 array to big uint by big endian
# warning : input's endian must be big endian
# input : big endian uint8 array
# output : cpu native endian uint16/uint32/uint64
# return value version
# openArray version
template fromBytesBE*[T: BigUint](input: openArray[uint8]): T {.autoSizeOpt.} =
  var output: T
  when defined(nostd):
    output = 0
    unroll(b, 0, sizeof(T) - 1):
      output = output or (input[b].T shl ((sizeof(T) - 1 - b) * 8))
  else:
    const size: int = sizeof(T)
    copyMem(addr output, addr input[0], size)
    when not BE:
      beToNative(output, output)
  output

# fromBytesBE : uint8 array to big uint by big endian
# warning : input's endian must be big endian
# input : big endian uint8 array
# output : cpu native endian uint16/uint32/uint64
# mutable parameter version
# ptr array version
template fromBytesBE*[T: BigUint, N: static int](input: ptr array[N, uint8], output: ptr T): void {.autoSizeOpt.} =
  static:
    doAssert N == sizeof(T), "The total size of input and output must be same."

  when defined(nostd):
    output[] = 0
    unroll(b, 0, sizeof(T) - 1):
      output[] = output[] or (input[b].T shl ((sizeof(T) - 1 - b) * 8))
  else:
    const size: int = sizeof(T)
    copyMem(output, input, size)
    when not BE:
      beToNative(output, output)

# fromBytesBE : uint8 array to big uint by big endian
# warning : input's endian must be big endian
# input : big endian uint8 array
# output : cpu native endian uint16/uint32/uint64
# return value version
# ptr array version
template fromBytesBE*[T: BigUint, N: static int](input: ptr array[N, uint8]): T {.autoSizeOpt.} =
  static:
    doAssert N == sizeof(T), "The total size of input and output must be same."
  var output: T
  when defined(nostd):
    output = 0
    unroll(b, 0, sizeof(T) - 1):
      output = output or (input[b].T shl ((sizeof(T) - 1 - b) * 8))
  else:
    const size: int = sizeof(T)
    copyMem(addr output, input, size)
    when not BE:
      beToNative(output, output)
  output

# fromBytesBE : uint8 array to big uint by big endian
# warning : input's endian must be big endian
# input : big endian uint8 array
# output : cpu native endian uint16/uint32/uint64
# mutable parameter version
# ptr UncheckedArray version
template fromBytesBE*[T: BigUint](input: ptr UncheckedArray[uint8], output: ptr T): void {.autoSizeOpt.} =
  when defined(nostd):
    output[] = 0
    unroll(b, 0, sizeof(T) - 1):
      output[] = output[] or (input[b].T shl ((sizeof(T) - 1 - b) * 8))
  else:
    const size: int = sizeof(T)
    copyMem(output, input, size)
    when not BE:
      beToNative(output, output)

# fromBytesBE : uint8 array to big uint by big endian
# warning : input's endian must be big endian
# input : big endian uint8 array
# output : cpu native endian uint16/uint32/uint64
# return value version
# ptr UncheckedArray version
template fromBytesBE*[T: BigUint](input: ptr UncheckedArray[uint8]): T {.autoSizeOpt.} =
  var output: T
  when defined(nostd):
    output = 0
    unroll(b, 0, sizeof(T) - 1):
      output = output or (input[b].T shl ((sizeof(T) - 1 - b) * 8))
  else:
    const size: int = sizeof(T)
    copyMem(addr output, input, size)
    when not BE:
      beToNative(output, output)
  output

# toBytesLE : big uint to uint8 array by little endian
# warning : output's endian will be little endian
# input : cpu native endian uint16/uint32/uint64
# output : little endian uint8 array
# mutable parameter version
# array version
template toBytesLE*[N: static int, T: BigUint](input: T, output: var array[N, uint8]): void {.autoSizeOpt.} =
  static:
    doAssert N == sizeof(T), "The total size of input and output must be same."

  when defined(nostd):
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input shr (b * 8)) and 0xFF)
  else:
    const size: int = sizeof(T)
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input shr (b * 8)) and 0xFF)

# toBytesLE : big uint to uint8 array by little endian
# warning : output's endian will be little endian
# input : cpu native endian uint16/uint32/uint64
# output : little endian uint8 array
# return value version
# array version
template toBytesLE*[T: BigUint](input: T): array[sizeof(T), uint8] {.autoSizeOpt.} =
  var output: array[sizeof(T), uint8]
  when defined(nostd):
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input shr (b * 8)) and 0xFF)
  else:
    const size: int = sizeof(T)
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input shr (b * 8)) and 0xFF)
  output

# toBytesLE : big uint to uint8 array by little endian
# warning : output's endian will be little endian
# input : cpu native endian uint16/uint32/uint64
# output : little endian uint8 array
# mutable parameter version
# slicearray version
template toBytesLE*[N: static int, T: BigUint](input: T, output: slicearray[N, uint8]): void {.autoSizeOpt.} =
  static:
    doAssert N == sizeof(T), "The total size of input and output must be same."

  when defined(nostd):
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input shr (b * 8)) and 0xFF)
  else:
    const size: int = sizeof(T)
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input shr (b * 8)) and 0xFF)

# toBytesLE : big uint to uint8 array by little endian
# warning : output's endian will be little endian
# input : cpu native endian uint16/uint32/uint64
# output : little endian uint8 array
# mutable parameter version
# openArray version
template toBytesLE*[T: BigUint](input: T, output: openArray[uint8]): void {.autoSizeOpt.} =
  when defined(nostd):
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input shr (b * 8)) and 0xFF)
  else:
    const size: int = sizeof(T)
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input shr (b * 8)) and 0xFF)

# toBytesLE : big uint to uint8 array by little endian
# warning : output's endian will be little endian
# input : cpu native endian uint16/uint32/uint64
# output : little endian uint8 array
# mutable parameter version
# ptr array version
template toBytesLE*[N: static int, T: BigUint](input: ptr T, output: ptr array[N, uint8]): void {.autoSizeOpt.} =
  static:
    doAssert N == sizeof(T), "The total size of input and output must be same."

  when defined(nostd):
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input[] shr (b * 8)) and 0xFF)
  else:
    const size: int = sizeof(T)
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input[] shr (b * 8)) and 0xFF)

# toBytesLE : big uint to uint8 array by little endian
# warning : output's endian will be little endian
# input : cpu native endian uint16/uint32/uint64
# output : little endian uint8 array
# return value version
# ptr array version
template toBytesLE*[T: BigUint](input: ptr T): array[sizeof(T), uint8] {.autoSizeOpt.} =
  var output: array[sizeof(T), uint8]
  when defined(nostd):
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input[] shr (b * 8)) and 0xFF)
  else:
    const size: int = sizeof(T)
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input[] shr (b * 8)) and 0xFF)
  output

# toBytesLE : big uint to uint8 array by little endian
# warning : output's endian will be little endian
# input : cpu native endian uint16/uint32/uint64
# output : little endian uint8 array
# mutable parameter version
# ptr UncheckedArray version
template toBytesLE*[T: BigUint](input: ptr T, output: ptr UncheckedArray[uint8]): void {.autoSizeOpt.} =
  when defined(nostd):
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input[] shr (b * 8)) and 0xFF)
  else:
    const size: int = sizeof(T)
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input[] shr (b * 8)) and 0xFF)

# toBytesBE : big uint to uint8 array by big endian
# warning : output's endian will be big endian
# input : cpu native endian uint16/uint32/uint64
# output : big endian uint8 array
# mutable parameter version
# array version
template toBytesBE*[N: static int, T: BigUint](input: T, output: var array[N, uint8]): void {.autoSizeOpt.} =
  static:
    doAssert N == sizeof(T), "The total size of input and output must be same."

  when defined(nostd):
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input shr ((sizeof(T) - 1 - b) * 8)) and 0xFF)
  else:
    const size: int = sizeof(T)
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input shr ((sizeof(T) - 1 - b) * 8)) and 0xFF)

# toBytesBE : big uint to uint8 array by big endian
# warning : output's endian will be big endian
# input : cpu native endian uint16/uint32/uint64
# output : big endian uint8 array
# return value version
# array version
template toBytesBE*[T: BigUint](input: T): array[sizeof(T), uint8] {.autoSizeOpt.} =
  var output: array[sizeof(T), uint8]
  when defined(nostd):
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input shr ((sizeof(T) - 1 - b) * 8)) and 0xFF)
  else:
    const size: int = sizeof(T)
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input shr ((sizeof(T) - 1 - b) * 8)) and 0xFF)
  output

# toBytesBE : big uint to uint8 array by big endian
# warning : output's endian will be big endian
# input : cpu native endian uint16/uint32/uint64
# output : big endian uint8 array
# mutable parameter version
# slicearray version
template toBytesBE*[N: static int, T: BigUint](input: T, output: slicearray[N, uint8]): void {.autoSizeOpt.} =
  static:
    doAssert N == sizeof(T), "The total size of input and output must be same."

  when defined(nostd):
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input shr ((sizeof(T) - 1 - b) * 8)) and 0xFF)
  else:
    const size: int = sizeof(T)
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input shr ((sizeof(T) - 1 - b) * 8)) and 0xFF)

# toBytesBE : big uint to uint8 array by big endian
# warning : output's endian will be big endian
# input : cpu native endian uint16/uint32/uint64
# output : big endian uint8 array
# mutable parameter version
# openArray version
template toBytesBE*[T: BigUint](input: T, output: openArray[uint8]): void {.autoSizeOpt.} =
  when defined(nostd):
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input shr ((sizeof(T) - 1 - b) * 8)) and 0xFF)
  else:
    const size: int = sizeof(T)
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input shr ((sizeof(T) - 1 - b) * 8)) and 0xFF)

# toBytesBE : big uint to uint8 array by big endian
# warning : output's endian will be big endian
# input : cpu native endian uint16/uint32/uint64
# output : big endian uint8 array
# mutable parameter version
# ptr array version
template toBytesBE*[N: static int, T: BigUint](input: ptr T, output: ptr array[N, uint8]): void {.autoSizeOpt.} =
  static:
    doAssert N == sizeof(T), "The total size of input and output must be same."

  when defined(nostd):
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input[] shr ((sizeof(T) - 1 - b) * 8)) and 0xFF)
  else:
    const size: int = sizeof(T)
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input[] shr ((sizeof(T) - 1 - b) * 8)) and 0xFF)

# toBytesBE : big uint to uint8 array by big endian
# warning : output's endian will be big endian
# input : cpu native endian uint16/uint32/uint64
# output : big endian uint8 array
# return value version
# ptr array version
template toBytesBE*[T: BigUint](input: ptr T): array[sizeof(T), uint8] {.autoSizeOpt.} =
  var output: array[sizeof(T), uint8]
  when defined(nostd):
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input[] shr ((sizeof(T) - 1 - b) * 8)) and 0xFF)
  else:
    const size: int = sizeof(T)
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input[] shr ((sizeof(T) - 1 - b) * 8)) and 0xFF)
  output

# toBytesBE : big uint to uint8 array by big endian
# warning : output's endian will be big endian
# input : cpu native endian uint16/uint32/uint64
# output : big endian uint8 array
# mutable parameter version
# ptr UncheckedArray version
template toBytesBE*[T: BigUint](input: ptr T, output: ptr UncheckedArray[uint8]): void {.autoSizeOpt.} =
  when defined(nostd):
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input[] shr ((sizeof(T) - 1 - b) * 8)) and 0xFF)
  else:
    const size: int = sizeof(T)
    unroll(b, 0, sizeof(T) - 1):
      output[b] = uint8((input[] shr ((sizeof(T) - 1 - b) * 8)) and 0xFF)


