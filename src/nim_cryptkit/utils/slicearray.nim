import std/macros
import optmacro
import envconst

when Native and Unix and defined(antiForensic):
  import securetype

when defined(js):
  type
    slicearray*[len: static int, T] = distinct openArray[T]
else:
  type
    # slicearray type declaration
    slicearray*[len: static int, T] = distinct ptr UncheckedArray[T]

when defined(js):
  template toSliceArray*[N: static int, T](a: array[N, T], starts: static int, ends: static int): untyped =
    when not defined(forceDanger):
      static: doAssert starts >= 0 and ends < N and starts <= ends
    slicearray[ends - starts + 1, T](a.toOpenArray(starts, ends))

  template toSliceArray*[N: static int, T](a: slicearray[N, T], starts, ends: static int): untyped =
    when not defined(forceDanger):
      static: doAssert starts >= 0 and ends < N and starts <= ends
    slicearray[ends - starts + 1, T](a.toOpenArray(starts, ends))

  template toSliceArray*[T](a: openArray[T], starts: static int, ends: static int): untyped =
    when not defined(danger): doAssert a.len >= starts + ends - starts + 1
    slicearray[ends - starts + 1, T](a.toOpenArray(starts, ends))

  template toSliceArray*[N: static int, T](a: array[N, T], starts: int, ends: int, length: static int): untyped =
    when not defined(forceDanger):
      static: doAssert a.len >= length
    when not defined(danger): doAssert a.len >= starts + length
    slicearray[length, T](a.toOpenArray(starts, starts + length - 1))

  template toSliceArray*[N: static int, T](a: slicearray[N, T], starts, ends: int, length: static int): untyped =
    when not defined(forceDanger):
      static: doAssert a.len >= length
    when not defined(danger): doAssert a.len >= starts + length
    slicearray[length, T](a.toOpenArray(starts, starts + length - 1))

  template toSliceArray*[T](a: openArray[T], starts: int, ends: int, length: static int): untyped =
    when not defined(danger): doAssert a.len >= starts + length
    slicearray[length, T](a.toOpenArray(starts, starts + length - 1))
else:
  # offset : calculate offset by ptr UncheckedArray[T]
  # internal template : not exported
  template offset[T](p: ptr UncheckedArray[T], i: int): ptr UncheckedArray[T] =
    cast[ptr UncheckedArray[T]](cast[uint](p) + uint(i * sizeof(T)))

  # offset : calculate offset by slicearray[N, T]
  # internal template : not exported
  template offset[N: static int, T](p: slicearray[N, T], i: int): ptr UncheckedArray[T] =
    cast[ptr UncheckedArray[T]](cast[uint](p) + uint(i * sizeof(T)))

  # toSliceArray : create new slicearray by array[N, T] and static int type starts, ends
  # starts : starts index, static int
  # ends : ends index, static int
  # compile time bound check
  # usage : when slicing array where the starts and ends are determined at compile time
  template toSliceArray*[N: static int, T](a: array[N, T], starts: static int, ends: static int): untyped =
    when not defined(forceDanger):
      static: doAssert starts >= 0 and ends < N and starts <= ends
    cast[slicearray[ends - starts + 1, T]](addr a[starts])

  # toSliceArray : create new slicearray by ptr array[N, T] and static int type starts, ends
  # starts : starts index, static int
  # ends : ends index, static int
  # compile time bound check
  # usage : when slicing ptr array where the starts and ends are determined at compile time
  template toSliceArray*[N: static int, T](a: ptr array[N, T], starts: static int, ends: static int): untyped =
    when not defined(forceDanger):
      static: doAssert starts >= 0 and ends < N and starts <= ends
    cast[slicearray[ends - starts + 1, T]](addr a[starts])

  # toSliceArray : create new slicearray by slicearray[N, T] and static int type starts, ends
  # starts : starts index, static int
  # ends : ends index, static int
  # compile time bound check
  # usage : when slicing slicearray where the starts and ends are determined at compile time
  template toSliceArray*[N: static int, T](a: slicearray[N, T], starts, ends: static int): untyped =
    when not defined(forceDanger):
      static: doAssert starts >= 0 and ends < N and starts <= ends
    cast[slicearray[ends - starts + 1, T]](a.offset(starts))

  # toSliceArray : create new slicearray by openArray[T] and static int type starts, ends
  # starts : starts index, static int
  # ends : ends index, static int
  # run time bound check(deactivated in danger mode build)
  # usage : when slicing openArray where the starts and ends are determined at compile time
  template toSliceArray*[T](a: openArray[T], starts: static int, ends: static int): untyped =
    when not defined(danger): doAssert a.len >= starts + ends - starts + 1
    cast[slicearray[ends - starts + 1, T]](addr a[starts])

  template toSliceArray*[N: static int, T](a: ptr UncheckedArray[T], starts: static int, ends: static int): untyped =
    cast[slicearray[ends - starts + 1, T]](addr a[starts])

  # toSliceArray : create new slicearray by array[N, T] and int type starts, ends and static int type length
  # starts : starts index, int
  # ends : ends index, int
  # length : length, static int
  # compile time length check, run time bound check(deactivated in danger mode build)
  # usage : when creating a slicearray as an array in a loop (when the length is fixed)
  template toSliceArray*[N: static int, T](a: array[N, T], starts: int, ends: int, length: static int): untyped =
    when not defined(forceDanger):
      static: doAssert a.len >= length
    when not defined(danger): doAssert a.len >= starts + length
    cast[slicearray[length, T]](addr a[starts])

  # toSliceArray : create new slicearray by ptr array[N, T] and int type starts, ends and static int type length
  # starts : starts index, int
  # ends : ends index, int
  # length : length, static int
  # compile time length check, run time bound check(deactivated in danger mode build)
  # usage : when creating a slicearray as a ptr array in a loop (when the length is fixed)
  template toSliceArray*[N: static int, T](a: ptr array[N, T], starts: int, ends: int, length: static int): untyped =
    when not defined(forceDanger):
      static: doAssert a.len >= length
    when not defined(danger): doAssert a.len >= starts + length
    cast[slicearray[length, T]](addr a[starts])

  # toSliceArray : create new slicearray by slicearray[N, T] and int type starts, ends and static int type length
  # starts : starts index, int
  # ends : ends index, int
  # length : length, static int
  # compile time length check, run time bound check(deactivated in danger mode build)
  # usage : when creating a slicearray as a slicearray in a loop (when the length is fixed)
  template toSliceArray*[N: static int, T](a: slicearray[N, T], starts, ends: int, length: static int): untyped =
    when not defined(forceDanger):
      static: doAssert a.len >= length
    when not defined(danger): doAssert a.len >= starts + length
    cast[slicearray[length, T]](a.offset(starts))

  # toSliceArray : create new slicearray by openArray[T] and int type starts, ends and static int type length
  # starts : starts index, int
  # ends : ends index, int
  # length : length, static int
  # compile time length check, run time bound check(deactivated in danger mode build)
  # usage : when creating a slicearray as openArray in a loop (when the length is fixed)
  template toSliceArray*[T](a: openArray[T], starts: int, ends: int, length: static int): untyped =
    when not defined(danger): doAssert a.len >= starts + length
    cast[slicearray[length, T]](addr a[starts])

  template toSliceArray*[T](a: ptr UncheckedArray[T], starts: int, ends: int, length: static int): untyped =
    cast[slicearray[length, T]](addr a[starts])

# castTo : cast slicearray[N, T] to slicearray[sizeof(T) * N div sizeof(U), U]
# usage : when passing a slicearray of a different type as an argument to a function that receives it
proc castTo*[N: static int, T, U](s: slicearray[N, T], NewType: typedesc[U]): auto {.inline.} =
  const oldSize = sizeof(T)
  const newSize = sizeof(U)
  const newLength = (N * oldSize) div newSize
  static: doAssert (N * oldSize) mod newSize == 0
  result = cast[slicearray[newLength, U]](s)

# addr : get address of slicearray by index
# index : int
# run time bound check(deactivated in danger mode build)
template `addr`*[L: static int, T](s: slicearray[L, T], index: int): pointer =
  when not defined(danger): doAssert index >= 0 and index < L
  addr s[index]

# addr : get address of slicearray by index
# index : static int
# compile time bound check
template `addr`*[L: static int, T](s: slicearray[L, T], index: static int): pointer =
  static: doAssert index >= 0 and index < L
  addr s[index]

when defined(js):
  template `[]`*[L: static int, T](s: slicearray[L, T], index: int): T =
    when not defined(danger): doAssert index >= 0 and index < L
    openArray[T](s)[index]

  template `[] =`*[L: static int, T](s: slicearray[L, T], index: int, value: T) =
    when not defined(danger): doAssert index >= 0 and index < L
    openArray[T](s)[index] = value

  template `[]`*[L: static int, T](s: slicearray[L, T], index: static int): T =
    static: doAssert index >= 0 and index < L
    openArray[T](s)[index]

  template `[] =`*[L: static int, T](s: slicearray[L, T], index: static int, value: T) =
    static: doAssert index >= 0 and index < L
    openArray[T](s)[index] = value
else:
  # read only indexing : get index and return value
  # index : static int
  # compile time bound check
  template `[]`*[L: static int, T](s: slicearray[L, T], index: static int): T =
    static: doAssert index >= 0 and index < L
    cast[ptr UncheckedArray[T]](s)[index]

  # mutable indexing : get index and set value
  # index : static int
  # compile time bound check
  template `[] =`*[L: static int, T](s: slicearray[L, T], index: static int, value: T) =
    static: doAssert index >= 0 and index < L
    cast[ptr UncheckedArray[T]](s)[index] = value

  # read only indexing : get index and return value
  # index : int
  # run time bound check(deactivated in danger mode build)
  template `[]`*[L: static int, T](s: slicearray[L, T], index: int): T =
    when not defined(danger): doAssert index >= 0 and index < L
    cast[ptr UncheckedArray[T]](s)[index]

  # mutable indexing : get index and set value
  # index : int
  # run time bound check(deactivated in danger mode build)
  template `[] =`*[L: static int, T](s: slicearray[L, T], index: int, value: T) =
    when not defined(danger): doAssert index >= 0 and index < L
    cast[ptr UncheckedArray[T]](s)[index] = value

# items : get all items in slicearray
# usage : when iterating over a slicearray
iterator items*[L: static int, T](s: slicearray[L, T]): T =
  for i in 0 ..< L:
    yield s[i]

# mitems : get all items in slicearray
# usage : when iterating over a slicearray
iterator mitems*[L: static int, T](s: slicearray[L, T]): var T =
  for i in 0 ..< L:
    yield s[i]

# toString opeartor : convert slicearray to string
# usage : when printing a slicearray
template `$`*[L: static int, T](s: slicearray[L, T]): string =
  var output: string = "["
  for i in static(0 ..< L):
    output.add $s[i]
    if i < L - 1:
      output.add ", "
    output.add "]"
#[
# static indexing : get index and return static value
# index : static int
# return : static T
# usage : when accessing a static(const) array in static(const) index
template `[]`*[N, T](arr: static array[N, T], index: static int): static T =
  arr[index]
]#
# backreference operator : slicearray to slicearry
template `[]`*[L: static int, T](s: slicearray[L, T]): slicearray[L, T] =
  s

# toArray : convert slicearray to array
template toArray*[L: static int, T](s: slicearray[L, T]): array[L, T] =
  var output: array[L, T]
  # use copyMem when not in js, nimvm, pipelineC
  when not(defined(js) and defined(nimvm) and defined(pipelinec)):
    copyMem(addr output[0], addr s[0], sizeof(T) * L)
  # else use unroll to copy elements
  else:
    unroll(i, 0, L - 1):
      output[i] = s[i]
  output

# backreference copy : copy slicearray to slicearray
# usage : when copying a slicearray to a slicearray
proc `[] =`*[N: static int, T](output: slicearray[N, T], input: slicearray[N, T]) {.inline.} =
  # use copyMem when not in js, nimvm, pipelineC
  when not(defined(js) and defined(nimvm) and defined(pipelinec)):
    copyMem(addr output[0], addr input[0], N * sizeof(T))
  # else use unroll to copy elements
  else:
    unroll(i, 0, N - 1):
      output[i] = input[i]

# backreference copy : copy array to slicearray
# usage : when copying an array to a slicearray
proc `[] =`*[N: static int, T](output: slicearray[N, T], input: array[N, T]) {.inline.} =
  # use copyMem when not in js, nimvm, pipelineC
  when not(defined(js) and defined(nimvm) and defined(pipelinec)):
    copyMem(addr output[0], addr input[0], N * sizeof(T))
  # else use unroll to copy elements
  else:
    unroll(i, 0, N - 1):
      output[i] = input[i]

# backreference copy : copy ptr array to slicearray
# usage : when copying a ptr array to a slicearray
proc `[] =`*[N: static int, T](output: slicearray[N, T], input: ptr array[N, T]) {.inline.} =
  # use copyMem when not in js, nimvm, pipelineC
  when not(defined(js) and defined(nimvm) and defined(pipelinec)):
    copyMem(addr output[0], addr input[0], N * sizeof(T))
  # else use unroll to copy elements
  else:
    unroll(i, 0, N - 1):
      output[i] = input[i]
