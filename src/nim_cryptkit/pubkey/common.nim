import std/sysrand


type
  PubKeyError* = object of CatchableError
  Rng* = proc(buffer: var openArray[uint8]) {.gcsafe, raises: [].}

proc systemRng*(buffer: var openArray[uint8]): void {.gcsafe, raises: [].} =
  if not urandom(buffer):
    raise newException(Defect, "system CSPRNG unavailable")
