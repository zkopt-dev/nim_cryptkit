type
  ResultKind* = enum
    Success = 0,
    Failure = 1

  Result*[T, E] = object
    case kind*: ResultKind
    of Success:
      when T isnot void:
        value*: T
    of Failure:
      error*: E
