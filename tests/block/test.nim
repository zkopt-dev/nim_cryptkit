import strutils, os

proc convertCtoNimLiteral() =
  let inputPath = "input.txt"
  let outputPath = "output.txt"

  if not fileExists(inputPath):
    echo "에러: " & inputPath & " 파일이 존재하지 않습니다."
    return

  let content = readFile(inputPath)

  let tokens = content.split({'\n', '\r', ' ', '\t', ','})

  var cleanTokens: seq[string] = @[]

  for token in tokens:
    let trimmed = token.strip()
    if trimmed.startsWith("0x"):
      var hexNum = trimmed
      if hexNum.endsWith("L"):
        hexNum = hexNum[0 .. ^2]

      cleanTokens.add(hexNum & "")

  if cleanTokens.len == 0:
    echo "변환할 16진수 데이터를 찾지 못했습니다."
    return

  # 3. 한 줄에 8개씩 묶어서 포맷팅합니다.
  var outputLines: seq[string] = @[]
  let itemsPerLine = 8

  var i = 0
  while i < cleanTokens.len:
    let nextCount = min(itemsPerLine, cleanTokens.len - i)
    let chunk = cleanTokens[i ..< i + nextCount]

    let lineStr = "      " & chunk.join(", ") & ","
    outputLines.add(lineStr)

    i += itemsPerLine

  writeFile(outputPath, outputLines.join("\n") & "\n")
  echo "변환 완료! " & outputPath & " 파일을 확인하세요."

convertCtoNimLiteral()

#[
proc convertData(filename: string) =
  if not fileExists(filename):
    echo "❌ 파일을 찾을 수 없습니다: ", filename
    return

  let content = readFile(filename)
  var result = ""

  for line in content.splitLines():
    let trimmedLine = line.strip()
    if trimmedLine == "": continue

    # 1. 콤마(,)를 기준으로 분리
    let parts = trimmedLine.split(',')
    var formattedParts: seq[string] = @[]

    for p in parts:
      let token = p.strip()
      if token.startsWith("0x"):
        # 0x... 형식 뒤에 'u32 추가
        formattedParts.add(token & "'u32")
      elif token != "":
        # 혹시 0x 형식이 아닌 다른 데이터가 있어도 보존
        formattedParts.add(token)

    # 2. 다시 콤마와 공백으로 합치기
    var newLine = formattedParts.join(", ")

    # 3. 원본 행 끝에 콤마가 있었다면 추가 (마지막 행 처리용)
    if trimmedLine.endsWith(","):
      newLine.add(",")

    # 4. 앞에 스페이스 4칸 추가해서 결과에 누적
    result.add("    " & newLine & "\n")

  writeFile("output.txt", result)
  echo "✅ 변환 완료! 'output.txt' 파일을 확인하세요."

# 실행부
if fileExists("input.txt"):
  convertData("input.txt")
else:
  # 테스트용 파일 자동 생성
  let testData = """
0x30fb40d4, 0x9fa0ff0b, 0x6beccd2f, 0x3f258c7a,
0xbfd4af27, 0x88bbbdb5, 0xe2034090, 0x98d09675
"""
  writeFile("input.txt", testData.strip())
  convertData("input.txt")

  ]#
