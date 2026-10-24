const
  # unix environment
  Unix*: bool = defined(linux) or defined(freebsd) or defined(openbsd) or defined(netbsd) or
                defined(dragonfly) or defined(solaris) or defined(aix) or defined(macosx) or defined(android)

  # native environment
  Native*: bool = defined(c) or defined(cpp) or defined(objc)

  # web environment
  Web*: bool = defined(js) or defined(wasm32)

  # cpu bits
  CPUBits*: int = sizeof(uint) * 8

  CPUBytes*: int = sizeof(uint)

  # little endian environment
  LE*: bool = cpuEndian == littleEndian

  # big endian environment
  BE*: bool = cpuEndian == bigEndian

  # bsd environment
  BSD*: bool = defined(freebsd) or defined(openbsd) or defined(netbsd) or defined(dragonfly)

  # x86 environment
  X86*: bool = defined(i386) or defined(amd64)

  # arm environment
  ARM*: bool = defined(arm) or defined(arm64)

  # mips environment
  MIPS*: bool = defined(mips) or defined(mipsel) or defined(mips64) or defined(mips64el)

  # powerpc environment
  PPC*: bool = defined(powerpc) or defined(powerpc64) or defined(powerpc64el)

  # sparc environment
  SPARC*: bool = defined(sparc) or defined(sparc64)

  # riscv environment
  RISCV*: bool = defined(riscv32) or defined(riscv64)

  LoongArch*: bool = defined(loongarch64)

when CPUBits == 64:
  type UINT* = uint64
elif CPUBits == 32:
  type UINT* = uint32
elif CPUBits == 16:
  type UINT* = uint16
else:
  type UINT* = uint8

