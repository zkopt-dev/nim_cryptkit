
import std/macros
import envconst

proc replaceNodes(node: NimNode, target: string, replacement: NimNode): NimNode =
  if node.kind == nnkIdent and node.strVal == target:
    return replacement

  result = copyNimNode(node)
  for child in node:
    result.add(replaceNodes(child, target, replacement))

macro unroll*(i: untyped, startExp, stopExp: static int, stepOrBody: untyped, bodyExp: untyped = nil): untyped =
  var step = 1
  var body: NimNode

  if bodyExp == nil:
    body = stepOrBody
  else:
    step = stepOrBody.intVal.int
    body = bodyExp

  result = newStmtList()
  let targetName = i.strVal

  when defined(sizeOpt):
    if startExp <= stopExp:
      let rangeNode = if step == 1: newTree(nnkInfix, ident"..", newLit(startExp), newLit(stopExp))
                      else: newTree(nnkCall, ident"countup", newLit(startExp), newLit(stopExp), newLit(step))
      result.add(newTree(nnkForStmt, i, rangeNode, body))
    else:
      let rangeNode = newTree(nnkCall, ident"countdown", newLit(startExp), newLit(stopExp), newLit(step))
      result.add(newTree(nnkForStmt, i, rangeNode, body))
  else:
    if startExp <= stopExp:
      var val = startExp
      while val <= stopExp:
        result.add(replaceNodes(body, targetName, newLit(val)))
        val += step
    else:
      var val = startExp
      while val >= stopExp:
        result.add(replaceNodes(body, targetName, newLit(val)))
        val -= step

macro autoSizeOpt*(n: untyped): untyped =
  n.expectKind({nnkProcDef, nnkTemplateDef})

  let targetKind = when defined(sizeOpt): nnkProcDef else: nnkTemplateDef

  result = newTree(targetKind)
  for child in n:
    result.add(child)

  if targetKind == nnkProcDef and result[3].kind == nnkEmpty:
    result[3] = newTree(nnkFormalParams, ident"void")

  var pragmas = result[4]
  if pragmas.kind == nnkPragma:
    var newPragmas = newNimNode(nnkPragma)
    for p in pragmas:
      if p.kind == nnkIdent and p.strVal == "autoSizeOpt":
        continue
      newPragmas.add(p)
    result[4] = newPragmas

macro autoTemplateOpt*(n: untyped): untyped =
  n.expectKind({nnkProcDef, nnkTemplateDef})

  let targetKind = when defined(templateOpt): nnkTemplateDef else: nnkProcDef

  result = newTree(targetKind)
  for child in n:
    result.add(child)

  if targetKind == nnkProcDef and result[3].kind == nnkEmpty:
    result[3] = newTree(nnkFormalParams, ident"void")

  var pragmas = result[4]
  if pragmas.kind == nnkPragma:
    var newPragmas = newNimNode(nnkPragma)
    for p in pragmas:
      if p.kind == nnkIdent and p.strVal == "autoTemplateOpt":
        continue
      newPragmas.add(p)
    result[4] = newPragmas

macro optimise*(n: untyped): untyped =
  proc transform(node: NimNode): NimNode =
    if node.kind == nnkForStmt:
      let iter = node[1]
      if (iter.kind == nnkCall) and (iter[0].kind == nnkIdent) and (iter[0].strVal == "static"):
        when defined(sizeOpt):
          var newNode = copyNimNode(node)
          newNode.add(node[0])
          newNode.add(iter[1])
          newNode.add(transform(node[2]))
          return newNode
        else:
          return node

    elif node.kind == nnkWhenStmt:
      when defined(sizeOpt):
        result = newTree(nnkIfStmt)
        for child in node:
          var branch = copyNimTree(child)
          if branch.kind in {nnkElifBranch, nnkElse, nnkElifExpr}:
            let lastIdx = branch.len - 1
            branch[lastIdx] = transform(branch[lastIdx])
          result.add(branch)
        return result
      else:
        discard

    result = copyNimNode(node)
    for child in node:
      result.add(transform(child))

  result = transform(n)


template fastCopy*[T](output: var openArray[T], outputIndex: int, input: openArray[T], inputIndex: int, length: int) =
  when Native:
    let size: int = length * sizeof(T)
    copyMem(addr output[outputIndex], addr input[inputIndex], size)
  else:
    for i in 0 ..< length:
      output[outputIndex + i] = input[inputIndex + i]

template fastZero*[T](source: var openArray[T], index: int, length: int) =
  when Native:
    let size: int = length * sizeof(T)
    zeroMem(addr source[index], size)
  else:
    for i in 0 ..< length:
      source[index + i] = T(0x00)

template fastCopy*[T](output: var openArray[T], outputIndex: int, input: openArray[T], inputIndex: int, length: static int) =
  when Native:
    const size: int = length * sizeof(T)
    copyMem(addr output[outputIndex], addr input[inputIndex], size)
  else:
    for i in static(0 ..< length):
      output[outputIndex + i] = input[inputIndex + i]

template fastZero*[T](source: var openArray[T], index: int, length: static int) =
  when Native:
    const size: int = length * sizeof(T)
    zeroMem(addr source[index], size)
  else:
    for i in static(0 ..< length):
      source[index + i] = T(0x00)

when defined(js):
  template copyMem*(dest, source: pointer; size: int) = discard
  template zeroMem*(dest: pointer; size: int) = discard

  proc rewriteMemCalls(node: NimNode): NimNode =
    let k = node.kind

    if k == nnkCall or k == nnkCommand:
      if node[0].kind == nnkIdent and node[0].strVal == "zeroMem":
        let firstArg = node[1]
        if (firstArg.kind in {nnkCall, nnkCommand, nnkPrefix}) and eqIdent(firstArg[0], "addr"):
          let addrArg = firstArg[1]
          if addrArg.kind == nnkBracketExpr:
            let source = addrArg[0]
            let index = addrArg[1]
            let sizeNode = node[2]

            return quote do:
              fastZero(`source`, `index`, `sizeNode` div sizeof(`source`[0]))

      elif node[0].kind == nnkIdent and node[0].strVal == "copyMem":
        let firstArg = node[1]
        let secondArg = node[2]
        if (firstArg.kind in {nnkCall, nnkCommand, nnkPrefix}) and eqIdent(firstArg[0], "addr") and
           (secondArg.kind in {nnkCall, nnkCommand, nnkPrefix}) and eqIdent(secondArg[0], "addr"):
          let destAddr = firstArg[1]
          let srcAddr = secondArg[1]
          if destAddr.kind == nnkBracketExpr and srcAddr.kind == nnkBracketExpr:
            let output = destAddr[0]
            let outputIndex = destAddr[1]
            let input = srcAddr[0]
            let inputIndex = srcAddr[1]
            let sizeNode = node[3]

            return quote do:
              fastCopy(`output`, `outputIndex`, `input`, `inputIndex`, `sizeNode` div sizeof(`input`[0]))

    if node.len > 0:
      result = copyNimNode(node)
      for child in node:
        result.add(rewriteMemCalls(child))
    else:
      result = node

  macro autoMemOpt*(body: untyped): untyped =
    result = rewriteMemCalls(body)

else:
  macro autoMemOpt*(body: untyped): untyped =
    result = body
