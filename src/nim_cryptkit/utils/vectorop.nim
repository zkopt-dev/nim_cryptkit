import slicearray
import optmacro

template `and`*[N: static int, T](a, b: array[N, T]): array[N, T] {.autoSizeOpt.} =
  var output: array[N, T]

  unroll(i, 0, N - 1):
    output[i] = a[i] and b[i]

  output

template `or`*[N: static int, T](a, b: array[N ,T]): array[N, T] {.autoSizeOpt.} =
  var output: array[N, T]

  unroll(i, 0, N - 1):
    output[i] = a[i] or b[i]

  output

template `xor`*[N: static int, T](a, b: array[N, T]): array[N, T] {.autoSizeOpt.} =
  var output: array[N, T]

  unroll(i, 0, N - 1):
    output[i] = a[i] xor b[i]

  output

template `not`*[N: static int, T](a: array[N, T]): array[N, T] {.autoSizeOpt.} =
  var output: array[N, T]

  unroll(i, 0, N - 1):
    output[i] = not a[i]

  output

template `nand`*[N: static int, T](a, b: array[N, T]): array[N, T] {.autoSizeOpt.} =
  var output: array[N, T]

  unroll(i, 0, N - 1):
    output[i] = not (a[i] and b[i])

  output

template `nor`*[N: static int, T](a, b: array[N, T]): array[N, T] {.autoSizeOpt.} =
  var output: array[N, T]

  unroll(i, 0, N - 1):
    output[i] = not (a[i] or b[i])

  output

template `andnot`*[N: static int, T](a, b: array[N, T]): array[N, T] {.autoSizeOpt.} =
  var output: array[N, T]

  unroll(i, 0, N - 1):
    output[i] = a[i] and not (b[i])

  output

template `ornot`*[N: static int, T](a, b: array[N, T]): array[N, T] {.autoSizeOpt.} =
  var output: array[N, T]

  unroll(i, 0, N - 1):
    output[i] = a[i] or not (b[i])

  output

template `shl`*[N: static int, T](input: array[N, T], shift: int): array[N, T] {.autoSizeOpt.} =
  var output: array[N, T]

  if shift < N * sizeof(T) * 8:
    const elementBits: int = sizeof(T) * 8
    let elementShift: int = shift div elementBits
    let bitShift: int = shift mod elementBits

    if bitShift == 0:
      for i in countdown(N - 1, elementShift):
        output[i] = input[i - elementShift]
    else:
      let invBitShift: int = elementBits - bitShift
      for i in countdown(N - 1, elementShift + 1):
        output[i] = (input[i - elementShift] shl bitShift) or (input[i - elementShift - 1] shr invBitShift)
      output[elementShift] = input[0] shl bitShift

  output

template `shr`*[N: static int, T](input: array[N, T], shift: int): array[N, T] {.autoSizeOpt.} =
  var output: array[N, T]

  if shift < N * sizeof(T) * 8:
    const elementBits: int = sizeof(T) * 8
    let elementShift: int = shift div elementBits
    let bitShift: int = shift mod elementBits

    if bitShift == 0:
      for i in 0 ..< (N - elementShift):
        output[i] = input[i + elementShift]
    else:
      let invBitShift: int = elementBits - bitShift
      for i in 0 ..< (N - elementShift - 1):
        output[i] = (input[i + elementShift] shr bitShift) or (input[i + elementShift + 1] shl invBitShift)
      output[N - 1 - elementShift] = input[N - 1] shr bitShift

  output

template `shl`*[N: static int, T](input: array[N, T], shift: static int): array[N, T] {.autoSizeOpt.} =
  var output: array[N, T]

  when shift < N * sizeof(T) * 8:
    const elementBits: int = sizeof(T) * 8
    const elementShift: int = shift div elementBits
    const bitShift: int = shift mod elementBits

    when bitShift == 0:
      unroll(i, N - 1, elementShift):
        output[i] = input[i - elementShift]
    else:
      const invBitShift: int = elementBits - bitShift
      unroll(i, N - 1, elementShift + 1):
        output[i] = (input[i - elementShift] shl bitShift) or (input[i - elementShift - 1] shr invBitShift)
      output[elementShift] = input[0] shl bitShift

  output

template `shr`*[N: static int, T](input: array[N, T], shift: static int): array[N, T] {.autoSizeOpt.} =
  var output: array[N, T]

  when shift < N * sizeof(T) * 8:
    const elementBits: int = sizeof(T) * 8
    const elementShift: int = shift div elementBits
    const bitShift: int = shift mod elementBits

    when bitShift == 0:
      unroll(i, N - elementShift - 1):
        output[i] = input[i + elementShift]
    else:
      const invBitShift: int = elementBits - bitShift
      unroll(i,N - elementShift - 2):
        output[i] = (input[i + elementShift] shr bitShift) or (input[i + elementShift + 1] shl invBitShift)
      output[N - 1 - elementShift] = input[N - 1] shr bitShift

  output

template rotateLeftBits*[N: static int, T](input: array[N, T], shift: int): array[N, T] =
  ((input shl shift.int) or (input shr (int(sizeof(T)) * 8) - shift.int))

template rotateRightBits*[N: static int, T](input: array[N, T], shift: int): array[N, T] =
  ((input shr shift.int) or (input shl (int(sizeof(T)) * 8) - shift.int))

template rotateLeftBits*[N: static int, T](input: array[N, T], shift: static int): array[N, T] =
  ((input shl shift.int) or (input shr (int(sizeof(T)) * 8) - shift.int))

template rotateRightBits*[N: static int, T](input: array[N, T], shift: static int): array[N, T] =
  ((input shr shift.int) or (input shl (int(sizeof(T)) * 8) - shift.int))

template `==`*[N: static int, T](a, b: array[N, T]): bool {.autoSizeOpt.} =
  var check: bool = true
  unroll(i, 0, N - 1):
    if a[i] != b[i]:
      check = false
      break
  check

template `<`*[N: static int, T](a, b: array[N, T]): bool {.autoSizeOpt.} =
  var check: bool = false
  unroll(i, N - 1, 0):
    if a[i] < b[i]:
      check = true
      break
    if a[i] > b[i]:
      check = false
      break
  check

template `!=`*[N: static int, T](a, b: array[N, T]): bool {.autoSizeOpt.} =
  not (a == b)

template `>=`*[N: static int, T](a, b: array[N, T]): bool {.autoSizeOpt.} =
  not (a < b)

template `>`*[N: static int, T](a, b: array[N, T]): bool {.autoSizeOpt.} =
  (b < a)

template `<=`*[N: static int, T](a, b: array[N, T]): bool {.autoSizeOpt.} =
  not (a > b)

template `+`*[N: static int, T](a, b: array[N, T]): array[N, T] =
  var output: array[N, T]
  unroll(i, 0, N - 1):
    output[i] = a[i] + b[i]
  output

template `-`*[N: static int, T](a, b: array[N, T]): array[N, T] =
  var output: array[N, T]
  unroll(i, 0, N - 1):
    output[i] = a[i] - b[i]
  output

template `*`*[N: static int, T](a, b: array[N, T]): array[N, T] =
  var output: array[N, T]
  unroll(i, 0, N - 1):
    output[i] = a[i] * b[i]
  output

template `div`*[N: static int, T: SomeInteger](a, b: array[N, T]): array[N, T] =
  var output: array[N, T]
  unroll(i, 0, N - 1):
    output[i] = a[i] div b[i]
  output

template `mod`*[N: static int, T: SomeInteger](a, b: array[N, T]): array[N, T] =
  var output: array[N, T]
  unroll(i, 0, N - 1):
    output[i] = a[i] mod b[i]
  output

template `/`*[N: static int, T: SomeFloat](a, b: array[N, T]): array[N, T] =
  var output: array[N, T]
  unroll(i, 0, N - 1):
    output[i] = a[i] / b[i]
  output
