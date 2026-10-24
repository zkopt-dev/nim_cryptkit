import ../utils/endian
import ../utils/digits
import ../utils/bitutils
import ../utils/envconst
import ../utils/slicearray
import ../utils/optmacro
import ../utils/errorutils
import ../utils/vectorop
import std/[monotimes, times]
import std/bitops

type
  ModeError* = enum
    UnpackedBlock
    PaddingError
    TagError

proc ansiX923*(input: openArray[uint8], blockSize: int): seq[uint8] {.autoTemplateOpt.} =
  let inputLen: int = input.len
  let padLen: int = blockSize - (inputLen mod blockSize)
  var output: seq[uint8] = newSeq[uint8](padLen + inputLen)

  copyMem(addr output[0], addr input[0], inputLen)
  zeroMem(addr output[inputLen], padLen - 1)
  output[inputLen + padLen - 1] = uint8(padLen)

  output

proc unansiX923*(input: openArray[uint8], blockSize: int): int {.autoTemplateOpt.} =
  let inputLen: int = input.len

  if inputLen == 0 or inputLen mod blockSize != 0: return 0

  let padLen = int(input[inputLen - 1])

  if padLen <= 0 or padLen > blockSize: return 0

  for i in (inputLen - padLen) ..< (inputLen - 1):
    if input[i] != 0x00'u8: return 0

  return inputLen - padLen

proc iso10126*(input: openArray[uint8], blockSize: int): seq[uint8] {.autoTemplateOpt.} =
  let inputLen: int = input.len
  let padLen: int = blockSize - (inputLen mod blockSize)
  var output: seq[uint8] = newSeq[uint8](padLen + inputLen)
  copyMem(addr output[0], addr input[0], inputLen)
  var random: seq[uint8] = newSeq[uint8](padLen - 1)
  # call random generator
  copyMem(addr output[inputLen], addr random[0], padLen - 1)
  output[inputLen + padLen - 1] = uint8(padLen)

  output

proc uniso10126*(input: openArray[uint8], blockSize: int): int {.autoTemplateOpt.} =
  let inputLen: int = input.len

  if inputLen == 0 or inputLen mod blockSize != 0: return 0

  let padLen = int(input[inputLen - 1])
  if padLen <= 0 or padLen > blockSize: return 0

  return inputLen - padLen

proc pkcs7*(input: openArray[uint8], blockSize: int): seq[uint8] {.autoTemplateOpt.} =
  let inputLen: int = input.len
  let padLen: int = blockSize - (inputLen mod blockSize)
  var output: seq[uint8] = newSeq[uint8](padLen + inputLen)
  copyMem(addr output[0], addr input[0], inputLen)
  for i in inputLen ..< (inputLen + padLen):
    output[i] = uint8(padLen)

  output

proc unpkcs7*(input: openArray[uint8], blockSize: int): int {.autoTemplateOpt.} =
  let inputLen: int = input.len

  if inputLen == 0 or inputLen mod blockSize != 0: return -1

  let padLen = int(input[inputLen - 1])
  if padLen <= 0 or padLen > blockSize: return -1

  for i in (inputLen - padLen) ..< inputLen:
    if int(input[i]) != padLen: return -1

  return inputLen - padLen

proc iso78164*(input: openArray[uint8], blockSize: int): seq[uint8] {.autoTemplateOpt.} =
  let inputLen: int = input.len
  let padLen: int = blockSize - (inputLen mod blockSize)
  var output: seq[uint8] = newSeq[uint8](padLen + inputLen)
  copyMem(addr output[0], addr input[0], inputLen)
  output[inputLen] = 0x80'u8
  zeroMem(addr output[inputLen + 1], padLen - 1)

  output

proc uniso78164*(input: openArray[uint8], blockSize: int): int {.autoTemplateOpt.} =
  let inputLen: int = input.len
  if inputLen == 0 or inputLen mod blockSize != 0: return 0

  var i = inputLen - 1
  while i >= inputLen - blockSize:
    if input[i] == 0x80'u8:
      return i
    elif input[i] != 0x00'u8:
      return 0
    dec(i)

  return 0
