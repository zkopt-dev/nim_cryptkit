import std/strutils

proc hexBytes*(hex: string): seq[byte] =
  doAssert (hex.len and 1) == 0
  result = newSeq[byte](hex.len div 2)
  for i in 0..<result.len:
    result[i] = byte(parseHexInt(hex[i * 2 .. i * 2 + 1]))

proc fixedBytes*[N: static[int]](hex: string): array[N, uint8] =
  let decoded = hexBytes(hex)
  doAssert decoded.len == N
  for i in 0..<N: result[i] = decoded[i]
