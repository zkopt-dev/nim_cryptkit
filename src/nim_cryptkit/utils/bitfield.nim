type
  KernelSec* = bitstrcut[8]
    enable*: bitrange[0]
    mode*: bitrange[1..2]
    option*: bitrange[3..6]
    se*: bitrange[7]

    contract:
      disable(enable) =>disable(mode, se)

      require(mode == 3) => enable(se)

      exclude(option[0], se)

template getType(bitlength: static int): untyped =
  when bitlength >= 8:
    uint8
  elif bitlength >= 16:
    uint16
  elif bitlength >= 32:
    uint32
  elif bitlength >= 64:
    uint64

type
  bitstruct[bitlength: static range[1..64]] = getType(bitlength)

  bitrange[]
