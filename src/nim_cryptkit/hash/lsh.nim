import ../utils/endian
import ../utils/digits
import ../utils/bitutils
import ../utils/envconst
import ../utils/slicearray
import ../utils/optmacro
import ../utils/errorutils
import std/[monotimes, times]
import std/bitops
import strutils

const
  # LSH block size
  LSH_256_BLOCK_SIZE*: int = 128
  LSH_512_BLOCK_SIZE*: int = 256

  # LSH state size
  LSH_256_STATE_SIZE*: int = 64
  LSH_512_STATE_SIZE*: int = 128

  # LSH round number
  ROUND_CONSTANT_NUMBER*: int = 8

  # LSH hash size 
  LSH_224_HASH_SIZE*: int = 28
  LSH_256_HASH_SIZE*: int = 32
  LSH_384_HASH_SIZE*: int = 48
  LSH_512_HASH_SIZE*: int = 64
  LSH_512_224_HASH_SIZE*: int = 28
  LSH_512_256_HASH_SIZE*: int = 32

  # even round rotate constant for 256 series
  ROT_EVEN_ALPHA_256: int = 29
  ROT_EVEN_BETA_256: int = 1

  # odd round rotate constant for 256 series
  ROT_ODD_ALPHA_256: int = 5
  ROT_ODD_BETA_256: int = 17

  # even round rotate constant for 512 series
  ROT_EVEN_ALPHA_512*: int = 23
  ROT_EVEN_BETA_512*: int = 59

  # odd round rotate constant for 512 series
  ROT_ODD_ALPHA_512*: int = 7
  ROT_ODD_BETA_512*: int = 3

  # round number
  NUM_STEPS_256*: int = 26
  NUM_STEPS_512*: int = 28

type
  # LSH kind
  LSHKind* = enum
    LSH224
    LSH256
    LSH384
    LSH512
    LSH512_224
    LSH512_256

  # LSH generic context
  LSHCtx*[kind: static LSHKind, size: static int] = object
    when kind == LSH224 or kind == LSH256:
      index*: int
      cvL*: array[8, uint32]
      cvR*: array[8, uint32]
      buffer*: array[128, uint8]
      evenLeftState*: array[8, uint32]
      oddLeftState*: array[8, uint32]
      evenRightState*: array[8, uint32]
      oddRightState*: array[8, uint32]
    elif kind == LSH384 or kind == LSH512 or kind == LSH512_224 or kind == LSH512_256:
      index*: int
      cvL*: array[8, uint64]
      cvR*: array[8, uint64]
      buffer*: array[256, uint8]
      evenLeftState*: array[8, uint64]
      oddLeftState*: array[8, uint64]
      evenRightState*: array[8, uint64]
      oddRightState*: array[8, uint64]

  # LSH context 
  LSH224Ctx* = LSHCtx[LSH224, 28]
  LSH256Ctx* = LSHCtx[LSH256, 32]
  LSH384Ctx* = LSHCtx[LSH384, 48]
  LSH512Ctx* = LSHCtx[LSH512, 64]
  LSH512_224Ctx* = LSHCtx[LSH512_224, 28]
  LSH512_256Ctx* = LSHCtx[LSH512_256, 32]

const
  # constant K for 256 series
  K256: array[208, uint32] = [
    0x917caf90'u32, 0x6c1b10a2'u32, 0x6f352943'u32, 0xcf778243'u32, 0x2ceb7472'u32, 0x29e96ff2'u32, 0x8a9ba428'u32, 0x2eeb2642'u32,
    0x0e2c4021'u32, 0x872bb30e'u32, 0xa45e6cb2'u32, 0x46f9c612'u32, 0x185fe69e'u32, 0x1359621b'u32, 0x263fccb2'u32, 0x1a116870'u32,
    0x3a6c612f'u32, 0xb2dec195'u32, 0x02cb1f56'u32, 0x40bfd858'u32, 0x784684b6'u32, 0x6cbb7d2e'u32, 0x660c7ed8'u32, 0x2b79d88a'u32,
    0xa6cd9069'u32, 0x91a05747'u32, 0xcdea7558'u32, 0x00983098'u32, 0xbecb3b2e'u32, 0x2838ab9a'u32, 0x728b573e'u32, 0xa55262b5'u32,
    0x745dfa0f'u32, 0x31f79ed8'u32, 0xb85fce25'u32, 0x98c8c898'u32, 0x8a0669ec'u32, 0x60e445c2'u32, 0xfde295b0'u32, 0xf7b5185a'u32,
    0xd2580983'u32, 0x29967709'u32, 0x182df3dd'u32, 0x61916130'u32, 0x90705676'u32, 0x452a0822'u32, 0xe07846ad'u32, 0xaccd7351'u32,
    0x2a618d55'u32, 0xc00d8032'u32, 0x4621d0f5'u32, 0xf2f29191'u32, 0x00c6cd06'u32, 0x6f322a67'u32, 0x58bef48d'u32, 0x7a40c4fd'u32,
    0x8beee27f'u32, 0xcd8db2f2'u32, 0x67f2c63b'u32, 0xe5842383'u32, 0xc793d306'u32, 0xa15c91d6'u32, 0x17b381e5'u32, 0xbb05c277'u32,
    0x7ad1620a'u32, 0x5b40a5bf'u32, 0x5ab901a2'u32, 0x69a7a768'u32, 0x5b66d9cd'u32, 0xfdee6877'u32, 0xcb3566fc'u32, 0xc0c83a32'u32,
    0x4c336c84'u32, 0x9be6651a'u32, 0x13baa3fc'u32, 0x114f0fd1'u32, 0xc240a728'u32, 0xec56e074'u32, 0x009c63c7'u32, 0x89026cf2'u32,
    0x7f9ff0d0'u32, 0x824b7fb5'u32, 0xce5ea00f'u32, 0x605ee0e2'u32, 0x02e7cfea'u32, 0x43375560'u32, 0x9d002ac7'u32, 0x8b6f5f7b'u32,
    0x1f90c14f'u32, 0xcdcb3537'u32, 0x2cfeafdd'u32, 0xbf3fc342'u32, 0xeab7b9ec'u32, 0x7a8cb5a3'u32, 0x9d2af264'u32, 0xfacedb06'u32,
    0xb052106e'u32, 0x99006d04'u32, 0x2bae8d09'u32, 0xff030601'u32, 0xa271a6d6'u32, 0x0742591d'u32, 0xc81d5701'u32, 0xc9a9e200'u32,
    0x02627f1e'u32, 0x996d719d'u32, 0xda3b9634'u32, 0x02090800'u32, 0x14187d78'u32, 0x499b7624'u32, 0xe57458c9'u32, 0x738be2c9'u32,
    0x64e19d20'u32, 0x06df0f36'u32, 0x15d1cb0e'u32, 0x0b110802'u32, 0x2c95f58c'u32, 0xe5119a6d'u32, 0x59cd22ae'u32, 0xff6eac3c'u32,
    0x467ebd84'u32, 0xe5ee453c'u32, 0xe79cd923'u32, 0x1c190a0d'u32, 0xc28b81b8'u32, 0xf6ac0852'u32, 0x26efd107'u32, 0x6e1ae93b'u32,
    0xc53c41ca'u32, 0xd4338221'u32, 0x8475fd0a'u32, 0x35231729'u32, 0x4e0d3a7a'u32, 0xa2b45b48'u32, 0x16c0d82d'u32, 0x890424a9'u32,
    0x017e0c8f'u32, 0x07b5a3f5'u32, 0xfa73078e'u32, 0x583a405e'u32, 0x5b47b4c8'u32, 0x570fa3ea'u32, 0xd7990543'u32, 0x8d28ce32'u32,
    0x7f8a9b90'u32, 0xbd5998fc'u32, 0x6d7a9688'u32, 0x927a9eb6'u32, 0xa2fc7d23'u32, 0x66b38e41'u32, 0x709e491a'u32, 0xb5f700bf'u32,
    0x0a262c0f'u32, 0x16f295b9'u32, 0xe8111ef5'u32, 0x0d195548'u32, 0x9f79a0c5'u32, 0x1a41cfa7'u32, 0x0ee7638a'u32, 0xacf7c074'u32,
    0x30523b19'u32, 0x09884ecf'u32, 0xf93014dd'u32, 0x266e9d55'u32, 0x191a6664'u32, 0x5c1176c1'u32, 0xf64aed98'u32, 0xa4b83520'u32,
    0x828d5449'u32, 0x91d71dd8'u32, 0x2944f2d6'u32, 0x950bf27b'u32, 0x3380ca7d'u32, 0x6d88381d'u32, 0x4138868e'u32, 0x5ced55c4'u32,
    0x0fe19dcb'u32, 0x68f4f669'u32, 0x6e37c8ff'u32, 0xa0fe6e10'u32, 0xb44b47b0'u32, 0xf5c0558a'u32, 0x79bf14cf'u32, 0x4a431a20'u32,
    0xf17f68da'u32, 0x5deb5fd1'u32, 0xa600c86d'u32, 0x9f6c7eb0'u32, 0xff92f864'u32, 0xb615e07f'u32, 0x38d3e448'u32, 0x8d5d3a6a'u32,
    0x70e843cb'u32, 0x494b312e'u32, 0xa6c93613'u32, 0x0beb2f4f'u32, 0x928b5d63'u32, 0xcbf66035'u32, 0x0cb82c80'u32, 0xea97a4f7'u32,
    0x592c0f3b'u32, 0x947c5f77'u32, 0x6fff49b9'u32, 0xf71a7e5a'u32, 0x1de8c0f5'u32, 0xc2569600'u32, 0xc4e4ac8c'u32, 0x823c9ce1'u32
  ]
  # constant K for 512 series
  K512: array[224, uint64] = [
    0x97884283c938982a'u64, 0xba1fca93533e2355'u64, 0xc519a2e87aeb1c03'u64, 0x9a0fc95462af17b1'u64,
    0xfc3dda8ab019a82b'u64, 0x02825d079a895407'u64, 0x79f2d0a7ee06a6f7'u64, 0xd76d15eed9fdf5fe'u64,
    0x1fcac64d01d0c2c1'u64, 0xd9ea5de69161790f'u64, 0xdebc8b6366071fc8'u64, 0xa9d91db711c6c94b'u64,
    0x3a18653ac9c1d427'u64, 0x84df64a223dd5b09'u64, 0x6cc37895f4ad9e70'u64, 0x448304c8d7f3f4d5'u64,
    0xea91134ed29383e0'u64, 0xc4484477f2da88e8'u64, 0x9b47eec96d26e8a6'u64, 0x82f6d4c8d89014f4'u64,
    0x527da0048b95fb61'u64, 0x644406c60138648d'u64, 0x303c0e8aa24c0edc'u64, 0xc787cda0cbe8ca19'u64,
    0x7ba46221661764ca'u64, 0x0c8cbc6acd6371ac'u64, 0xe336b836940f8f41'u64, 0x79cb9da168a50976'u64,
    0xd01da49021915cb3'u64, 0xa84accc7399cf1f1'u64, 0x6c4a992cee5aeb0c'u64, 0x4f556e6cb4b2e3e0'u64,
    0x200683877d7c2f45'u64, 0x9949273830d51db8'u64, 0x19eeeecaa39ed124'u64, 0x45693f0a0dae7fef'u64,
    0xedc234b1b2ee1083'u64, 0xf3179400d68ee399'u64, 0xb6e3c61b4945f778'u64, 0xa4c3db216796c42f'u64,
    0x268a0b04f9ab7465'u64, 0xe2705f6905f2d651'u64, 0x08ddb96e426ff53d'u64, 0xaea84917bc2e6f34'u64,
    0xaff6e664a0fe9470'u64, 0x0aab94d765727d8c'u64, 0x9aa9e1648f3d702e'u64, 0x689efc88fe5af3d3'u64,
    0xb0950ffea51fd98b'u64, 0x52cfc86ef8c92833'u64, 0xe69727b0b2653245'u64, 0x56f160d3ea9da3e2'u64,
    0xa6dd4b059f93051f'u64, 0xb6406c3cd7f00996'u64, 0x448b45f3ccad9ec8'u64, 0x079b8587594ec73b'u64,
    0x45a50ea3c4f9653b'u64, 0x22983767c1f15b85'u64, 0x7dbed8631797782b'u64, 0x485234be88418638'u64,
    0x842850a5329824c5'u64, 0xf6aca914c7f9a04c'u64, 0xcfd139c07a4c670c'u64, 0xa3210ce0a8160242'u64,
    0xeab3b268be5ea080'u64, 0xbacf9f29b34ce0a7'u64, 0x3c973b7aaf0fa3a8'u64, 0x9a86f346c9c7be80'u64,
    0xac78f5d7cabcea49'u64, 0xa355bddcc199ed42'u64, 0xa10afa3ac6b373db'u64, 0xc42ded88be1844e5'u64,
    0x9e661b271cff216a'u64, 0x8a6ec8dd002d8861'u64, 0xd3d2b629beb34be4'u64, 0x217a3a1091863f1a'u64,
    0x256ecda287a733f5'u64, 0xf9139a9e5b872fe5'u64, 0xac0535017a274f7c'u64, 0xf21b7646d65d2aa9'u64,
    0x048142441c208c08'u64, 0xf937a5dd2db5e9eb'u64, 0xa688dfe871ff30b7'u64, 0x9bb44aa217c5593b'u64,
    0x943c702a2edb291a'u64, 0x0cae38f9e2b715de'u64, 0xb13a367ba176cc28'u64, 0x0d91bd1d3387d49b'u64,
    0x85c386603cac940c'u64, 0x30dd830ae39fd5e4'u64, 0x2f68c85a712fe85d'u64, 0x4ffeecb9dd1e94d6'u64,
    0xd0ac9a590a0443ae'u64, 0xbae732dc99ccf3ea'u64, 0xeb70b21d1842f4d9'u64, 0x9f4eda50bb5c6fa8'u64,
    0x4949e69ce940a091'u64, 0x0e608dee8375ba14'u64, 0x983122cba118458c'u64, 0x4eeba696fbb36b25'u64,
    0x7d46f3630e47f27e'u64, 0xa21a0f7666c0dea4'u64, 0x5c22cf355b37cec4'u64, 0xee292b0c17cc1847'u64,
    0x9330838629e131da'u64, 0x6eee7c71f92fce22'u64, 0xc953ee6cb95dd224'u64, 0x3a923d92af1e9073'u64,
    0xc43a5671563a70fb'u64, 0xbc2985dd279f8346'u64, 0x7ef2049093069320'u64, 0x17543723e3e46035'u64,
    0xc3b409b00b130c6d'u64, 0x5d6aee6b28fdf090'u64, 0x1d425b26172ff6ed'u64, 0xcccfd041cdaf03ad'u64,
    0xfe90c7c790ab6cbf'u64, 0xe5af6304c722ca02'u64, 0x70f695239999b39e'u64, 0x6b8b5b07c844954c'u64,
    0x77bdb9bb1e1f7a30'u64, 0xc859599426ee80ed'u64, 0x5f9d813d4726e40a'u64, 0x9ca0120f7cb2b179'u64,
    0x8f588f583c182cbd'u64, 0x951267cbe9eccce7'u64, 0x678bb8bd334d520e'u64, 0xf6e662d00cd9e1b7'u64,
    0x357774d93d99aaa7'u64, 0x21b2edbb156f6eb5'u64, 0xfd1ebe846e0aee69'u64, 0x3cb2218c2f642b15'u64,
    0xe7e7e7945444ea4c'u64, 0xa77a33b5d6b9b47c'u64, 0xf34475f0809f6075'u64, 0xdd4932dce6bb99ad'u64,
    0xacec4e16d74451dc'u64, 0xd4a0a8d084de23d6'u64, 0x1bdd42f278f95866'u64, 0xeed3adbb938f4051'u64,
    0xcfcf7be8992f3733'u64, 0x21ade98c906e3123'u64, 0x37ba66711fffd668'u64, 0x267c0fc3a255478a'u64,
    0x993a64ee1b962e88'u64, 0x754979556301faaa'u64, 0xf920356b7251be81'u64, 0xc281694f22cf923f'u64,
    0x9f4b6481c8666b02'u64, 0xcf97761cfe9f5444'u64, 0xf220d7911fd63e9f'u64, 0xa28bd365f79cd1b0'u64,
    0xd39f5309b1c4b721'u64, 0xbec2ceb864fca51f'u64, 0x1955a0ddc410407a'u64, 0x43eab871f261d201'u64,
    0xeaafe64a2ed16da1'u64, 0x670d931b9df39913'u64, 0x12f868b0f614de91'u64, 0x2e5f395d946e8252'u64,
    0x72f25cbb767bd8f4'u64, 0x8191871d61a1c4dd'u64, 0x6ef67ea1d450ba93'u64, 0x2ea32a645433d344'u64,
    0x9a963079003f0f8b'u64, 0x74a0aeb9918cac7a'u64, 0x0b6119a70af36fa3'u64, 0x8d9896f202f0d480'u64,
    0x654f1831f254cd66'u64, 0x1318a47f0366a25e'u64, 0x65752076250b4e01'u64, 0xd1cd8eb888071772'u64,
    0x30c6a9793f4e9b25'u64, 0x154f684b1e3926ee'u64, 0x6c7ac0b1fe6312ae'u64, 0x262f88f4f3c5550d'u64,
    0xb4674a24472233cb'u64, 0x2bbd23826a090071'u64, 0xda95969b30594f66'u64, 0x9f5c47408f1e8a43'u64,
    0xf77022b88de9c055'u64, 0x64b7b36957601503'u64, 0xe73b72b06175c11a'u64, 0x55b87de8b91a6233'u64,
    0x1bb16e6b6955ff7f'u64, 0xe8e0a5ec7309719c'u64, 0x702c31cb89a8b640'u64, 0xfba387cfada8cde2'u64,
    0x6792db4677aa164c'u64, 0x1c6b1cc0b7751867'u64, 0x22ae2311d736dc01'u64, 0x0e3666a1d37c9588'u64,
    0xcd1fd9d4bf557e9a'u64, 0xc986925f7c7b0e84'u64, 0x9c5dfd55325ef6b0'u64, 0x9f2b577d5676b0dd'u64,
    0xfa6e21be21c062b3'u64, 0x8787dd782c8d7f83'u64, 0xd0d134e90e12dd23'u64, 0x449d087550121d96'u64,
    0xecf9ae9414d41967'u64, 0x5018f1dbf789934d'u64, 0xfa5b52879155a74c'u64, 0xca82d4d3cd278e7c'u64,
    0x688fdfdfe22316ad'u64, 0x0f6555a4ba0d030a'u64, 0xa2061df720f000f3'u64, 0xe1a57dc5622fb3da'u64,
    0xe6a842a8e8ed8153'u64, 0x690acdd3811ce09d'u64, 0x55adda18e6fcf446'u64, 0x4d57a8a0f4b60b46'u64,
    0xf86fbfc20539c415'u64, 0x74bafa5ec7100d19'u64, 0xa824151810f0f495'u64, 0x8723432791e38ebb'u64,
    0x8eeaeb91d66ed539'u64, 0x73d8a1549dfd7e06'u64, 0x0387f2ffe3f13a9b'u64, 0xa5004995aac15193'u64,
    0x682f81c73efdda0d'u64, 0x2fb55925d71d268d'u64, 0xcc392d2901e58a3d'u64, 0xaa666ab975724a42'u64
  ]

# block expand for even round
template expandBlockEven(ctx: var LSHCtx): void =
  when ctx.evenLeftState[0] is uint32:
    var tempEvenL, tempEvenR, tempOddL, tempOddR: array[8, uint32]
  elif ctx.evenLeftState[0] is uint64:
    var tempEvenL, tempEvenR, tempOddL, tempOddR: array[8, uint64]

  tempEvenL = ctx.evenLeftState
  tempEvenR = ctx.evenRightState
  tempOddL = ctx.oddLeftState
  tempOddR = ctx.oddRightState

  ctx.evenLeftState[0] = tempOddL[0] + tempEvenL[3]
  ctx.evenLeftState[1] = tempOddL[1] + tempEvenL[2]
  ctx.evenLeftState[2] = tempOddL[2] + tempEvenL[0]
  ctx.evenLeftState[3] = tempOddL[3] + tempEvenL[1]
  ctx.evenLeftState[4] = tempOddL[4] + tempEvenL[7]
  ctx.evenLeftState[5] = tempOddL[5] + tempEvenL[4]
  ctx.evenLeftState[6] = tempOddL[6] + tempEvenL[5]
  ctx.evenLeftState[7] = tempOddL[7] + tempEvenL[6]

  ctx.evenRightState[0] = tempOddR[0] + tempEvenR[3]
  ctx.evenRightState[1] = tempOddR[1] + tempEvenR[2]
  ctx.evenRightState[2] = tempOddR[2] + tempEvenR[0]
  ctx.evenRightState[3] = tempOddR[3] + tempEvenR[1]
  ctx.evenRightState[4] = tempOddR[4] + tempEvenR[7]
  ctx.evenRightState[5] = tempOddR[5] + tempEvenR[4]
  ctx.evenRightState[6] = tempOddR[6] + tempEvenR[5]
  ctx.evenRightState[7] = tempOddR[7] + tempEvenR[6]

# block expand for odd round
template expandBlockOdd(ctx: var LSHCtx): void =
  when ctx.oddLeftState[0] is uint32:
    var tempEvenL, tempEvenR, tempOddL, tempOddR: array[8, uint32]
  elif ctx.oddLeftState[0] is uint64:
    var tempEvenL, tempEvenR, tempOddL, tempOddR: array[8, uint64]

  tempEvenL = ctx.evenLeftState
  tempEvenR = ctx.evenRightState
  tempOddL = ctx.oddLeftState
  tempOddR = ctx.oddRightState

  ctx.oddLeftState[0] = tempEvenL[0] + tempOddL[3]
  ctx.oddLeftState[1] = tempEvenL[1] + tempOddL[2]
  ctx.oddLeftState[2] = tempEvenL[2] + tempOddL[0]
  ctx.oddLeftState[3] = tempEvenL[3] + tempOddL[1]
  ctx.oddLeftState[4] = tempEvenL[4] + tempOddL[7]
  ctx.oddLeftState[5] = tempEvenL[5] + tempOddL[4]
  ctx.oddLeftState[6] = tempEvenL[6] + tempOddL[5]
  ctx.oddLeftState[7] = tempEvenL[7] + tempOddL[6]

  ctx.oddRightState[0] = tempEvenR[0] + tempOddR[3]
  ctx.oddRightState[1] = tempEvenR[1] + tempOddR[2]
  ctx.oddRightState[2] = tempEvenR[2] + tempOddR[0]
  ctx.oddRightState[3] = tempEvenR[3] + tempOddR[1]
  ctx.oddRightState[4] = tempEvenR[4] + tempOddR[7]
  ctx.oddRightState[5] = tempEvenR[5] + tempOddR[4]
  ctx.oddRightState[6] = tempEvenR[6] + tempOddR[5]
  ctx.oddRightState[7] = tempEvenR[7] + tempOddR[6]

# xor states
template xorStates[T](cvL, cvR, subL, subR: var array[8, T]): void =
  for i in static(0 ..< 8):
    cvL[i] = cvL[i] xor subL[i]
    cvR[i] = cvR[i] xor subR[i]

# add block for even round
template addBlockEven(ctx: LSHCtx): void =
  xorStates(ctx.cvL, ctx.cvR, ctx.evenLeftState, ctx.evenRightState)

# add block for odd round
template addBlockOdd(ctx: LSHCtx): void =
  xorStates(ctx.cvL, ctx.cvR, ctx.oddLeftState, ctx.oddRightState)

const
  # GAMMA constant
  G_GAMMA256: array[8, int] = [0, 8, 16, 24, 24, 16, 8, 0]
  G_GAMMA512: array[8, int] = [0, 16, 32, 48, 8, 24, 40, 56]

# add block generic
template addBlock[T](cvL: var array[8, T], cvR: array[8, T]): void =
  for i in static(0 ..< 8):
    cvL[i] += cvR[i]

# xor constant generic
template xorConst[T](cvL: var array[8, T], constV: array[8, T]): void =
  for i in static(0 ..< 8):
    cvL[i] = cvL[i] xor T(constV[i])

# rotate message gamma for 256 series
template rotateMsgGamma(cvR: var array[8, uint32]): void =
  for i in static(1 .. 6):
    cvR[i] = rotateLeftBits(cvR[i], G_GAMMA256[i])

# rotate message gamma for 512 series
template rotateMsgGamma(cvR: var array[8, uint64]): void =
  for i in static(1 .. 7):
    cvR[i] = rotateLeftBits(cvR[i], G_GAMMA512[i])

# word permutation generic
template wordPerm[T: uint32|uint64](cvL, cvR: var array[8, T]): void =
  let temp0 = cvL[0]
  cvL[0] = cvL[6]
  cvL[6] = cvR[6]
  cvR[6] = cvR[2]
  cvR[2] = cvL[1]
  cvL[1] = cvL[4]
  cvL[4] = cvR[4]
  cvR[4] = cvR[0]
  cvR[0] = cvL[2]
  cvL[2] = cvL[5]
  cvL[5] = cvR[7]
  cvR[7] = cvR[1]
  cvR[1] = temp0

  let temp3 = cvL[3]
  cvL[3] = cvL[7]
  cvL[7] = cvR[5]
  cvR[5] = cvR[3]
  cvR[3] = temp3

# rotate block generic
template rotateBlock[T: uint32|uint64](cv: var array[8, T], value: static int): void =
  for i in static(0 ..< 8):
    cv[i] = rotateLeftBits(cv[i], value)

# load sub constant
template loadSC[T: uint32|uint64](sc: var array[8, T], index: int): void =
  for i in static(0 ..< 8):
    when T is uint32:
      sc[i] = K256[index + i]
    when T is uint64:
      sc[i] = K512[index + i]

# mix generic
template mix[T: uint32|uint64](cvL, cvR: var array[8, T], constV: array[8, T], rotAlpha, rotBeta: static int): void =
  addBlock(cvL, cvR)
  rotateBlock(cvL, rotAlpha)
  xorConst(cvL, constV)
  addBlock(cvR, cvL)
  rotateBlock(cvR, rotBeta)
  addBlock(cvL, cvR)
  rotateMsgGamma(cvR)

# lsh transform template for big endian
template lshTransform*[K: static LSHKind, S, N: static int](ctx: var LSHCtx[K, S], chunk: slicearray[N, uint8]): void {.autoSizeOpt.} =
  when LE:
    when K in {LSH224, LSH256}:
      var sc: array[8, uint32]
      copyMem(addr ctx.evenLeftState[0], addr chunk[0], 32)
      copyMem(addr ctx.evenRightState[0], addr chunk[32], 32)
      copyMem(addr ctx.oddLeftState[0], addr chunk[64], 32)
      copyMem(addr ctx.oddRightState[0], addr chunk[96], 32)
    else:
      var sc: array[8, uint64]
      copyMem(addr ctx.evenLeftState[0], addr chunk[0], 64)
      copyMem(addr ctx.evenRightState[0], addr chunk[64], 64)
      copyMem(addr ctx.oddLeftState[0], addr chunk[128], 64)
      copyMem(addr ctx.oddRightState[0], addr chunk[192], 64)
  else:
    when K in {LSH224, LSH256}:
      var sc: array[8, uint32]
      decodeLE(chunk.toSliceArray(0, 31), ctx.evenLeftState.toSliceArray(0, 7))
      decodeLE(chunk.toSliceArray(32, 63), ctx.evenRightState.toSliceArray(0, 7))
      decodeLE(chunk.toSliceArray(64, 95), ctx.oddLeftState.toSliceArray(0, 7))
      decodeLE(chunk.toSliceArray(96, 127), ctx.oddRightState.toSliceArray(0, 7))
    else:
      var sc: array[8, uint64]
      decodeLE(chunk.toSliceArray(0, 63), ctx.evenLeftState.toSliceArray(0, 7))
      decodeLE(chunk.toSliceArray(64, 127), ctx.evenRightState.toSliceArray(0, 7))
      decodeLE(chunk.toSliceArray(128, 191), ctx.oddLeftState.toSliceArray(0, 7))
      decodeLE(chunk.toSliceArray(192, 255), ctx.oddRightState.toSliceArray(0, 7))

  var constIndex: int = 0

  addBlockEven(ctx)
  loadSC(sc, constIndex)
  when K in {LSH224, LSH256}:
    mix(ctx.cvL, ctx.cvR, sc, ROT_EVEN_ALPHA_256, ROT_EVEN_BETA_256)
  else:
    mix(ctx.cvL, ctx.cvR, sc, ROT_EVEN_ALPHA_512, ROT_EVEN_BETA_512)
  wordPerm(ctx.cvL, ctx.cvR)
  constIndex += 8

  addBlockOdd(ctx)
  loadSC(sc, constIndex)
  when K in {LSH224, LSH256}:
    mix(ctx.cvL, ctx.cvR, sc, ROT_ODD_ALPHA_256, ROT_ODD_BETA_256)
  else:
    mix(ctx.cvL, ctx.cvR, sc, ROT_ODD_ALPHA_512, ROT_ODD_BETA_512)
  wordPerm(ctx.cvL, ctx.cvR)
  constIndex += 8

  const numSteps: int = when K in {LSH224, LSH256}: NUM_STEPS_256 else: NUM_STEPS_512
  for i in static(1 ..< (numSteps div 2)):
    expandBlockEven(ctx)
    addBlockEven(ctx)
    loadSC(sc, constIndex)
    when K in {LSH224, LSH256}:
      mix(ctx.cvL, ctx.cvR, sc, ROT_EVEN_ALPHA_256, ROT_EVEN_BETA_256)
    else:
      mix(ctx.cvL, ctx.cvR, sc, ROT_EVEN_ALPHA_512, ROT_EVEN_BETA_512)
    wordPerm(ctx.cvL, ctx.cvR)
    constIndex += 8

    expandBlockOdd(ctx)
    addBlockOdd(ctx)
    loadSC(sc, constIndex)
    when K in {LSH224, LSH256}:
      mix(ctx.cvL, ctx.cvR, sc, ROT_ODD_ALPHA_256, ROT_ODD_BETA_256)
    else:
      mix(ctx.cvL, ctx.cvR, sc, ROT_ODD_ALPHA_512, ROT_ODD_BETA_512)
    wordPerm(ctx.cvL, ctx.cvR)
    constIndex += 8

  expandBlockEven(ctx)
  addBlockEven(ctx)

# lsh init core
template lshInitC[K: static LSHKind, S: static int](ctx: var LSHCtx[K, S]): void =
  ctx.index = 0
  # zerofill buffer, evenLeftState, oddLeftState, evenRightState, oddRightState
  zeroMem(addr ctx.buffer[0], sizeof(ctx.buffer))
  zeroMem(addr ctx.evenLeftState[0], sizeof(ctx.evenLeftState))
  zeroMem(addr ctx.oddLeftState[0], sizeof(ctx.oddLeftState))
  zeroMem(addr ctx.evenRightState[0], sizeof(ctx.evenRightState))
  zeroMem(addr ctx.oddRightState[0], sizeof(ctx.oddRightState))

  # set initialise vector for each context
  when K == LSH224:
    ctx.cvL = [
      0x068608D3'u32, 0x62D8F7A7'u32, 0xD76652AB'u32, 0x4C600A43'u32, 0xBDC40AA8'u32, 0x1ECA0B68'u32, 0xDA1A89BE'u32, 0x3147D354'u32
    ]
    ctx.cvR = [
      0x707EB4F9'u32, 0xF65B3862'u32, 0x6B0B2ABE'u32, 0x56B8EC0A'u32, 0xCF237286'u32, 0xEE0D1727'u32, 0x33636595'u32, 0x8BB8D05F'u32
    ]
  elif K == LSH256:
    ctx.cvL = [
      0x46a10f1f'u32, 0xfddce486'u32, 0xb41443a8'u32, 0x198e6b9d'u32, 0x3304388d'u32, 0xb0f5a3c7'u32, 0xb36061c4'u32, 0x7adbd553'u32
    ]
    ctx.cvR = [
      0x105d5378'u32, 0x2f74de54'u32, 0x5c2f2d95'u32, 0xf2553fbe'u32, 0x8051357a'u32, 0x138668c8'u32, 0x47aa4484'u32, 0xe01afb41'u32
    ]
  elif K == LSH384:
    ctx.cvL = [
      0x53156A66292808F6'u64, 0xB2C4F362B204C2BC'u64, 0xB84B7213BFA05C4E'u64, 0x976CEB7C1B299F73'u64,
      0xDF0CC63C0570AE97'u64, 0xDA4441BAA486CE3F'u64, 0x6559F5D9B5F2ACC2'u64, 0x22DACF19B4B52A16'u64
    ]
    ctx.cvR = [
      0xBBCDACEFDE80953A'u64, 0xC9891A2879725B3E'u64, 0x7C9FE6330237E440'u64, 0xA30BA550553F7431'u64,
      0xBB08043FB34E3E30'u64, 0xA0DEC48D54618EAD'u64, 0x150317267464BC57'u64, 0x32D1501FDE63DC93'u64
    ]
  elif K == LSH512:
    ctx.cvL = [
      0xadd50f3c7f07094e'u64, 0xe3f3cee8f9418a4f'u64, 0xb527ecde5b3d0ae9'u64, 0x2ef6dec68076f501'u64,
      0x8cb994cae5aca216'u64, 0xfbb9eae4bba48cc7'u64, 0x650a526174725fea'u64, 0x1f9a61a73f8d8085'u64
    ]
    ctx.cvR = [
      0xb6607378173b539b'u64, 0x1bc99853b0c0b9ed'u64, 0xdf727fc19b182d47'u64, 0xdbef360cf893a457'u64,
      0x4981f5e570147e80'u64, 0xd00c4490ca7d3e30'u64, 0x5d73940c0e4ae1ec'u64, 0x894085e2edb2d819'u64
    ]
  elif K == LSH512_224:
    ctx.cvL = [
      0x0C401E9FE8813A55'u64, 0x4A5F446268FD3D35'u64, 0xFF13E452334F612A'u64, 0xF8227661037E354A'u64,
      0xA5F223723C9CA29D'u64, 0x95D965A11AED3979'u64, 0x01E23835B9AB02CC'u64, 0x52D49CBAD5B30616'u64
    ]
    ctx.cvR = [
      0x9E5C2027773F4ED3'u64, 0x66A5C8801925B701'u64, 0x22BBC85B4C6779D9'u64, 0xC13171A42C559C23'u64,
      0x31E2B67D25BE3813'u64, 0xD522C4DEED8E4D83'u64, 0xA79F5509B43FBAFE'u64, 0xE00D2CD88B4B6C6A'u64
    ]
  elif K == LSH512_256:
    ctx.cvL = [
      0x6DC57C33DF989423'u64, 0xD8EA7F6E8342C199'u64, 0x76DF8356F8603AC4'u64, 0x40F1B44DE838223A'u64,
      0x39FFE7CFC31484CD'u64, 0x39C4326CC5281548'u64, 0x8A2FF85A346045D8'u64, 0xFF202AA46DBDD61E'u64
    ]
    ctx.cvR = [
      0xCF785B3CD5FCDB8B'u64, 0x1F0323B64A8150BF'u64, 0xFF75D972F29EA355'u64, 0x2E567F30BF1CA9E1'u64,
      0xB596875BF8FF6DBA'u64, 0xFCCA39B089EF4615'u64, 0xECFF4017D020B4B6'u64, 0x7E77384C772ED802'u64
    ]

# lsh input core
template lshInputC[K: static LSHKind, S: static int](ctx: var LSHCtx[K, S], input: openArray[uint8]): void {.autoSizeOpt.} =
  let inputLen: int = input.len
  var check: bool = true

  if inputLen == 0:
    check = false

  if check:
    # set block size constant
    const blockSize: int = when K in {LSH224, LSH256}: LSH_256_BLOCK_SIZE else: LSH_512_BLOCK_SIZE
   
    var index: int = ctx.index
    let left: int = blockSize - index
    var position: int = 0

    if inputLen >= left:
      if left > 0:
        copyMem(addr ctx.buffer[index], addr input[0], left)
      lshTransform(ctx, ctx.buffer.toSliceArray(0, blockSize - 1))
      position = left
      index = 0

      while position + blockSize <= inputLen:
        lshTransform(ctx, input.toSliceArray(position, position + blockSize - 1, blockSize))
        position += blockSize

    let remain: int = inputLen - position
    if remain > 0:
      copyMem(addr ctx.buffer[index], addr input[position], remain)
      index += remain

    ctx.index = index

# lsh final core
template lshFinalC[K: static LSHKind, S: static int](ctx: var LSHCtx[K, S]): array[S, uint8] {.autoSizeOpt.} =
  # set output length 
  const OUTPUT_LENGTH: int = when K == LSH224: LSH_224_HASH_SIZE
                             elif K == LSH256: LSH_256_HASH_SIZE
                             elif K == LSH384: LSH_384_HASH_SIZE
                             elif K == LSH512: LSH_512_HASH_SIZE
                             elif K == LSH512_224: LSH_512_224_HASH_SIZE
                             elif K == LSH512_256: LSH_512_256_HASH_SIZE

  # delcare output
  var output: array[OUTPUT_LENGTH, uint8]
  var index = ctx.index
  const blockSize = when K in {LSH224, LSH256}: LSH_256_BLOCK_SIZE else: LSH_512_BLOCK_SIZE

  # when index is smaller than blockSize
  if index < blockSize:
    # padding
    ctx.buffer[index] = 0x80'u8
    if index + 1 < blockSize:
      zeroMem(addr ctx.buffer[index + 1], blockSize - index - 1)
  else:
    # transform bufffer first
    lshTransform(ctx, ctx.buffer.toSliceArray(0, blockSize - 1))

    # padding
    ctx.buffer[0] = 0x80'u8
    zeroMem(addr ctx.buffer[1], blockSize - 1)

  # transform buffer 
  lshTransform(ctx, ctx.buffer.toSliceArray(0, blockSize - 1))

  # xor cvL and cvR
  for i in static(0 ..< 8):
    ctx.cvL[i] = ctx.cvL[i] xor ctx.cvR[i]

  # encode ctx.cvL to output
  when cpuEndian == littleEndian:
    copyMem(addr output[0], addr ctx.cvL[0], OUTPUT_LENGTH)
  else:
    when K == LSH224:
      encodeLE(ctx.cvL.toSliceArray(0, 6), output.toSliceArray(0, 27), 7)
    elif K == LSH256:
      encodeLE(ctx.cvL, output, 8)
    elif K == LSH384:
      encodeLE(ctx.cvL.toSliceArray(0, 5), output.toSliceArray(0, 47), 6)
    elif K == LSH512:
      encodeLE(ctx.cvL, output, 8)
    elif K == LSH512_224:
      var temp: array[32, uint8]
      encodeLE(ctx.cvL.toSliceArray(0, 3), temp.toSliceArray(0, 31), 4)
      copyMem(addr output[0], addr temp[0], 28)
    elif K == LSH512_256:
      encodeLE(ctx.cvL.toSliceArray(0, 3), output.toSliceArray(0, 31), 4)

  output

# export wrappers
when defined(templateOpt):
  template lsh224Init*(ctx: var LSH224Ctx): void = lshInitC(ctx)
  template lsh224Input*(ctx: var LSH224Ctx, input: openArray[uint8]): void = lshInputC(ctx, input)
  template lsh224Final*(ctx: var LSH224Ctx): array[28, uint8] = lshFinalC(ctx)

  template lsh256Init*(ctx: var LSH256Ctx): void = lshInitC(ctx)
  template lsh256Input*(ctx: var LSH256Ctx, input: openArray[uint8]): void = lshInputC(ctx, input)
  template lsh256Final*(ctx: var LSH256Ctx): array[32, uint8] = lshFinalC(ctx)

  template lsh384Init*(ctx: var LSH384Ctx): void = lshInitC(ctx)
  template lsh384Input*(ctx: var LSH384Ctx, input: openArray[uint8]): void = lshInputC(ctx, input)
  template lsh384Final*(ctx: var LSH384Ctx): array[48, uint8] = lshFinalC(ctx)

  template lsh512Init*(ctx: var LSH512Ctx): void = lshInitC(ctx)
  template lsh512Input*(ctx: var LSH512Ctx, input: openArray[uint8]): void = lshInputC(ctx, input)
  template lsh512Final*(ctx: var LSH512Ctx): array[64, uint8] = lshFinalC(ctx)

  template lsh512_224Init*(ctx: var LSH512_224Ctx): void = lshInitC(ctx)
  template lsh512_224Input*(ctx: var LSH512_224Ctx, input: openArray[uint8]): void = lshInputC(ctx, input)
  template lsh512_224Final*(ctx: var LSH512_224Ctx): array[28, uint8] = lshFinalC(ctx)

  template lsh512_256Init*(ctx: var LSH512_256Ctx): void = lshInitC(ctx)
  template lsh512_256Input*(ctx: var LSH512_256Ctx, input: openArray[uint8]): void = lshInputC(ctx, input)
  template lsh512_256Final*(ctx: var LSH512_256Ctx): array[32, uint8] = lshFinalC(ctx)

  when Native:
    template lsh224Init*(ctx: ptr LSH224Ctx): void = lshInitC(ctx[])
    template lsh224Input*(ctx: ptr LSH224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = lshInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template lsh224Final*(ctx: ptr LSH224Ctx, output: ptr array[28, uint8]): void = output[] = lshFinalC(ctx[])

    template lsh256Init*(ctx: ptr LSH256Ctx): void = lshInitC(ctx[])
    template lsh256Input*(ctx: ptr LSH256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = lshInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template lsh256Final*(ctx: ptr LSH256Ctx, output: ptr array[32, uint8]): void = output[] = lshFinalC(ctx[])

    template lsh384Init*(ctx: ptr LSH384Ctx): void = lshInitC(ctx[])
    template lsh384Input*(ctx: ptr LSH384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = lshInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template lsh384Final*(ctx: ptr LSH384Ctx, output: ptr array[48, uint8]): void = output[] = lshFinalC(ctx[])

    template lsh512Init*(ctx: ptr LSH512Ctx): void = lshInitC(ctx[])
    template lsh512Input*(ctx: ptr LSH512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = lshInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template lsh512Final*(ctx: ptr LSH512Ctx, output: ptr array[64, uint8]): void = output[] = lshFinalC(ctx[])

    template lsh512_224Init*(ctx: ptr LSH512_224Ctx): void = lshInitC(ctx[])
    template lsh512_224Input*(ctx: ptr LSH512_224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = lshInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template lsh512_224Final*(ctx: ptr LSH512_224Ctx, output: ptr array[28, uint8]): void = output[] = lshFinalC(ctx[])

    template lsh512_256Init*(ctx: ptr LSH512_256Ctx): void = lshInitC(ctx[])
    template lsh512_256Input*(ctx: ptr LSH512_256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = lshInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template lsh512_256Final*(ctx: ptr LSH512_256Ctx, output: ptr array[32, uint8]): void = output[] = lshFinalC(ctx[])

else:
  when Native:
    proc lsh224Init*(ctx: var LSH224Ctx): void = lshInitC(ctx)
    proc lsh224Input*(ctx: var LSH224Ctx, input: openArray[uint8]): void = lshInputC(ctx, input)
    proc lsh224Final*(ctx: var LSH224Ctx): array[28, uint8] = lshFinalC(ctx)

    proc lsh256Init*(ctx: var LSH256Ctx): void = lshInitC(ctx)
    proc lsh256Input*(ctx: var LSH256Ctx, input: openArray[uint8]): void = lshInputC(ctx, input)
    proc lsh256Final*(ctx: var LSH256Ctx): array[32, uint8] = lshFinalC(ctx)

    proc lsh384Init*(ctx: var LSH384Ctx): void = lshInitC(ctx)
    proc lsh384Input*(ctx: var LSH384Ctx, input: openArray[uint8]): void = lshInputC(ctx, input)
    proc lsh384Final*(ctx: var LSH384Ctx): array[48, uint8] = lshFinalC(ctx)

    proc lsh512Init*(ctx: var LSH512Ctx): void = lshInitC(ctx)
    proc lsh512Input*(ctx: var LSH512Ctx, input: openArray[uint8]): void = lshInputC(ctx, input)
    proc lsh512Final*(ctx: var LSH512Ctx): array[64, uint8] = lshFinalC(ctx)

    proc lsh512_224Init*(ctx: var LSH512_224Ctx): void = lshInitC(ctx)
    proc lsh512_224Input*(ctx: var LSH512_224Ctx, input: openArray[uint8]): void = lshInputC(ctx, input)
    proc lsh512_224Final*(ctx: var LSH512_224Ctx): array[28, uint8] = lshFinalC(ctx)

    proc lsh512_256Init*(ctx: var LSH512_256Ctx): void = lshInitC(ctx)
    proc lsh512_256Input*(ctx: var LSH512_256Ctx, input: openArray[uint8]): void = lshInputC(ctx, input)
    proc lsh512_256Final*(ctx: var LSH512_256Ctx): array[32, uint8] = lshFinalC(ctx)

  when defined(c) or defined(objc):
    proc lsh224Init*(ctx: ptr LSH224Ctx): void {.exportc: "lsh224Init".} = lshInitC(ctx[])
    proc lsh224Input*(ctx: ptr LSH224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "lsh224Input".} = lshInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc lsh224Final*(ctx: ptr LSH224Ctx, output: ptr array[28, uint8]): void {.exportc: "lsh224Final".} = output[] = lshFinalC(ctx[])

    proc lsh256Init*(ctx: ptr LSH256Ctx): void {.exportc: "lsh256Init".} = lshInitC(ctx[])
    proc lsh256Input*(ctx: ptr LSH256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "lsh256Input".} = lshInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc lsh256Final*(ctx: ptr LSH256Ctx, output: ptr array[32, uint8]): void {.exportc: "lsh256Final".} = output[] = lshFinalC(ctx[])

    proc lsh384Init*(ctx: ptr LSH384Ctx): void {.exportc: "lsh384Init".} = lshInitC(ctx[])
    proc lsh384Input*(ctx: ptr LSH384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "lsh384Input".} = lshInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc lsh384Final*(ctx: ptr LSH384Ctx, output: ptr array[48, uint8]): void {.exportc: "lsh384Final".} = output[] = lshFinalC(ctx[])

    proc lsh512Init*(ctx: ptr LSH512Ctx): void {.exportc: "lsh512Init".} = lshInitC(ctx[])
    proc lsh512Input*(ctx: ptr LSH512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "lsh512Input".} = lshInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc lsh512Final*(ctx: ptr LSH512Ctx, output: ptr array[64, uint8]): void {.exportc: "lsh512Final".} = output[] = lshFinalC(ctx[])

    proc lsh512_224Init*(ctx: ptr LSH512_224Ctx): void {.exportc: "lsh512_224Init".} = lshInitC(ctx[])
    proc lsh512_224Input*(ctx: ptr LSH512_224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "lsh512_224Input".} = lshInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc lsh512_224Final*(ctx: ptr LSH512_224Ctx, output: ptr array[28, uint8]): void {.exportc: "lsh512_224Final".} = output[] = lshFinalC(ctx[])

    proc lsh512_256Init*(ctx: ptr LSH512_256Ctx): void {.exportc: "lsh512_256Init".} = lshInitC(ctx[])
    proc lsh512_256Input*(ctx: ptr LSH512_256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "lsh512_256Input".} = lshInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc lsh512_256Final*(ctx: ptr LSH512_256Ctx, output: ptr array[32, uint8]): void {.exportc: "lsh512_256Final".} = output[] = lshFinalC(ctx[])

  elif defined(cpp):
    proc lsh224Init*(ctx: ptr LSH224Ctx): void {.exportcpp: "lsh224Init".} = lshInitC(ctx[])
    proc lsh224Input*(ctx: ptr LSH224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "lsh224Input".} = lshInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc lsh224Final*(ctx: ptr LSH224Ctx, output: ptr array[28, uint8]): void {.exportcpp: "lsh224Final".} = output[] = lshFinalC(ctx[])

    proc lsh256Init*(ctx: ptr LSH256Ctx): void {.exportcpp: "lsh256Init".} = lshInitC(ctx[])
    proc lsh256Input*(ctx: ptr LSH256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "lsh256Input".} = lshInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc lsh256Final*(ctx: ptr LSH256Ctx, output: ptr array[32, uint8]): void {.exportcpp: "lsh256Final".} = output[] = lshFinalC(ctx[])

    proc lsh384Init*(ctx: ptr LSH384Ctx): void {.exportcpp: "lsh384Init".} = lshInitC(ctx[])
    proc lsh384Input*(ctx: ptr LSH384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "lsh384Input".} = lshInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc lsh384Final*(ctx: ptr LSH384Ctx, output: ptr array[48, uint8]): void {.exportcpp: "lsh384Final".} = output[] = lshFinalC(ctx[])

    proc lsh512Init*(ctx: ptr LSH512Ctx): void {.exportcpp: "lsh512Init".} = lshInitC(ctx[])
    proc lsh512Input*(ctx: ptr LSH512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "lsh512Input".} = lshInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc lsh512Final*(ctx: ptr LSH512Ctx, output: ptr array[64, uint8]): void {.exportcpp: "lsh512Final".} = output[] = lshFinalC(ctx[])

    proc lsh512_224Init*(ctx: ptr LSH512_224Ctx): void {.exportcpp: "lsh512_224Init".} = lshInitC(ctx[])
    proc lsh512_224Input*(ctx: ptr LSH512_224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "lsh512_224Input".} = lshInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc lsh512_224Final*(ctx: ptr LSH512_224Ctx, output: ptr array[28, uint8]): void {.exportcpp: "lsh512_224Final".} = output[] = lshFinalC(ctx[])

    proc lsh512_256Init*(ctx: ptr LSH512_256Ctx): void {.exportcpp: "lsh512_256Init".} = lshInitC(ctx[])
    proc lsh512_256Input*(ctx: ptr LSH512_256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "lsh512_256Input".} = lshInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc lsh512_256Final*(ctx: ptr LSH512_256Ctx, output: ptr array[32, uint8]): void {.exportcpp: "lsh512_256Final".} = output[] = lshFinalC(ctx[])
