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
  # declare SBox 1 ~ 8
  SBox1*: array[256, uint32] = [
    0x30fb40d4'u32, 0x9fa0ff0b'u32, 0x6beccd2f'u32, 0x3f258c7a'u32, 0x1e213f2f'u32, 0x9c004dd3'u32, 0x6003e540'u32, 0xcf9fc949'u32,
    0xbfd4af27'u32, 0x88bbbdb5'u32, 0xe2034090'u32, 0x98d09675'u32, 0x6e63a0e0'u32, 0x15c361d2'u32, 0xc2e7661d'u32, 0x22d4ff8e'u32,
    0x28683b6f'u32, 0xc07fd059'u32, 0xff2379c8'u32, 0x775f50e2'u32, 0x43c340d3'u32, 0xdf2f8656'u32, 0x887ca41a'u32, 0xa2d2bd2d'u32,
    0xa1c9e0d6'u32, 0x346c4819'u32, 0x61b76d87'u32, 0x22540f2f'u32, 0x2abe32e1'u32, 0xaa54166b'u32, 0x22568e3a'u32, 0xa2d341d0'u32,
    0x66db40c8'u32, 0xa784392f'u32, 0x004dff2f'u32, 0x2db9d2de'u32, 0x97943fac'u32, 0x4a97c1d8'u32, 0x527644b7'u32, 0xb5f437a7'u32,
    0xb82cbaef'u32, 0xd751d159'u32, 0x6ff7f0ed'u32, 0x5a097a1f'u32, 0x827b68d0'u32, 0x90ecf52e'u32, 0x22b0c054'u32, 0xbc8e5935'u32,
    0x4b6d2f7f'u32, 0x50bb64a2'u32, 0xd2664910'u32, 0xbee5812d'u32, 0xb7332290'u32, 0xe93b159f'u32, 0xb48ee411'u32, 0x4bff345d'u32,
    0xfd45c240'u32, 0xad31973f'u32, 0xc4f6d02e'u32, 0x55fc8165'u32, 0xd5b1caad'u32, 0xa1ac2dae'u32, 0xa2d4b76d'u32, 0xc19b0c50'u32,
    0x882240f2'u32, 0x0c6e4f38'u32, 0xa4e4bfd7'u32, 0x4f5ba272'u32, 0x564c1d2f'u32, 0xc59c5319'u32, 0xb949e354'u32, 0xb04669fe'u32,
    0xb1b6ab8a'u32, 0xc71358dd'u32, 0x6385c545'u32, 0x110f935d'u32, 0x57538ad5'u32, 0x6a390493'u32, 0xe63d37e0'u32, 0x2a54f6b3'u32,
    0x3a787d5f'u32, 0x6276a0b5'u32, 0x19a6fcdf'u32, 0x7a42206a'u32, 0x29f9d4d5'u32, 0xf61b1891'u32, 0xbb72275e'u32, 0xaa508167'u32,
    0x38901091'u32, 0xc6b505eb'u32, 0x84c7cb8c'u32, 0x2ad75a0f'u32, 0x874a1427'u32, 0xa2d1936b'u32, 0x2ad286af'u32, 0xaa56d291'u32,
    0xd7894360'u32, 0x425c750d'u32, 0x93b39e26'u32, 0x187184c9'u32, 0x6c00b32d'u32, 0x73e2bb14'u32, 0xa0bebc3c'u32, 0x54623779'u32,
    0x64459eab'u32, 0x3f328b82'u32, 0x7718cf82'u32, 0x59a2cea6'u32, 0x04ee002e'u32, 0x89fe78e6'u32, 0x3fab0950'u32, 0x325ff6c2'u32,
    0x81383f05'u32, 0x6963c5c8'u32, 0x76cb5ad6'u32, 0xd49974c9'u32, 0xca180dcf'u32, 0x380782d5'u32, 0xc7fa5cf6'u32, 0x8ac31511'u32,
    0x35e79e13'u32, 0x47da91d0'u32, 0xf40f9086'u32, 0xa7e2419e'u32, 0x31366241'u32, 0x051ef495'u32, 0xaa573b04'u32, 0x4a805d8d'u32,
    0x548300d0'u32, 0x00322a3c'u32, 0xbf64cddf'u32, 0xba57a68e'u32, 0x75c6372b'u32, 0x50afd341'u32, 0xa7c13275'u32, 0x915a0bf5'u32,
    0x6b54bfab'u32, 0x2b0b1426'u32, 0xab4cc9d7'u32, 0x449ccd82'u32, 0xf7fbf265'u32, 0xab85c5f3'u32, 0x1b55db94'u32, 0xaad4e324'u32,
    0xcfa4bd3f'u32, 0x2deaa3e2'u32, 0x9e204d02'u32, 0xc8bd25ac'u32, 0xeadf55b3'u32, 0xd5bd9e98'u32, 0xe31231b2'u32, 0x2ad5ad6c'u32,
    0x954329de'u32, 0xadbe4528'u32, 0xd8710f69'u32, 0xaa51c90f'u32, 0xaa786bf6'u32, 0x22513f1e'u32, 0xaa51a79b'u32, 0x2ad344cc'u32,
    0x7b5a41f0'u32, 0xd37cfbad'u32, 0x1b069505'u32, 0x41ece491'u32, 0xb4c332e6'u32, 0x032268d4'u32, 0xc9600acc'u32, 0xce387e6d'u32,
    0xbf6bb16c'u32, 0x6a70fb78'u32, 0x0d03d9c9'u32, 0xd4df39de'u32, 0xe01063da'u32, 0x4736f464'u32, 0x5ad328d8'u32, 0xb347cc96'u32,
    0x75bb0fc3'u32, 0x98511bfb'u32, 0x4ffbcc35'u32, 0xb58bcf6a'u32, 0xe11f0abc'u32, 0xbfc5fe4a'u32, 0xa70aec10'u32, 0xac39570a'u32,
    0x3f04442f'u32, 0x6188b153'u32, 0xe0397a2e'u32, 0x5727cb79'u32, 0x9ceb418f'u32, 0x1cacd68d'u32, 0x2ad37c96'u32, 0x0175cb9d'u32,
    0xc69dff09'u32, 0xc75b65f0'u32, 0xd9db40d8'u32, 0xec0e7779'u32, 0x4744ead4'u32, 0xb11c3274'u32, 0xdd24cb9e'u32, 0x7e1c54bd'u32,
    0xf01144f9'u32, 0xd2240eb1'u32, 0x9675b3fd'u32, 0xa3ac3755'u32, 0xd47c27af'u32, 0x51c85f4d'u32, 0x56907596'u32, 0xa5bb15e6'u32,
    0x580304f0'u32, 0xca042cf1'u32, 0x011a37ea'u32, 0x8dbfaadb'u32, 0x35ba3e4a'u32, 0x3526ffa0'u32, 0xc37b4d09'u32, 0xbc306ed9'u32,
    0x98a52666'u32, 0x5648f725'u32, 0xff5e569d'u32, 0x0ced63d0'u32, 0x7c63b2cf'u32, 0x700b45e1'u32, 0xd5ea50f1'u32, 0x85a92872'u32,
    0xaf1fbda7'u32, 0xd4234870'u32, 0xa7870bf3'u32, 0x2d3b4d79'u32, 0x42e04198'u32, 0x0cd0ede7'u32, 0x26470db8'u32, 0xf881814c'u32,
    0x474d6ad7'u32, 0x7c0c5e5c'u32, 0xd1231959'u32, 0x381b7298'u32, 0xf5d2f4db'u32, 0xab838653'u32, 0x6e2f1e23'u32, 0x83719c9e'u32,
    0xbd91e046'u32, 0x9a56456e'u32, 0xdc39200c'u32, 0x20c8c571'u32, 0x962bda1c'u32, 0xe1e696ff'u32, 0xb141ab08'u32, 0x7cca89b9'u32,
    0x1a69e783'u32, 0x02cc4843'u32, 0xa2f7c579'u32, 0x429ef47d'u32, 0x427b169c'u32, 0x5ac9f049'u32, 0xdd8f0f00'u32, 0x5c8165bf'u32
  ]
  SBox2*: array[256, uint32] = [
    0x1f201094'u32, 0xef0ba75b'u32, 0x69e3cf7e'u32, 0x393f4380'u32, 0xfe61cf7a'u32, 0xeec5207a'u32, 0x55889c94'u32, 0x72fc0651'u32,
    0xada7ef79'u32, 0x4e1d7235'u32, 0xd55a63ce'u32, 0xde0436ba'u32, 0x99c430ef'u32, 0x5f0c0794'u32, 0x18dcdb7d'u32, 0xa1d6eff3'u32,
    0xa0b52f7b'u32, 0x59e83605'u32, 0xee15b094'u32, 0xe9ffd909'u32, 0xdc440086'u32, 0xef944459'u32, 0xba83ccb3'u32, 0xe0c3cdfb'u32,
    0xd1da4181'u32, 0x3b092ab1'u32, 0xf997f1c1'u32, 0xa5e6cf7b'u32, 0x01420ddb'u32, 0xe4e7ef5b'u32, 0x25a1ff41'u32, 0xe180f806'u32,
    0x1fc41080'u32, 0x179bee7a'u32, 0xd37ac6a9'u32, 0xfe5830a4'u32, 0x98de8b7f'u32, 0x77e83f4e'u32, 0x79929269'u32, 0x24fa9f7b'u32,
    0xe113c85b'u32, 0xacc40083'u32, 0xd7503525'u32, 0xf7ea615f'u32, 0x62143154'u32, 0x0d554b63'u32, 0x5d681121'u32, 0xc866c359'u32,
    0x3d63cf73'u32, 0xcee234c0'u32, 0xd4d87e87'u32, 0x5c672b21'u32, 0x071f6181'u32, 0x39f7627f'u32, 0x361e3084'u32, 0xe4eb573b'u32,
    0x602f64a4'u32, 0xd63acd9c'u32, 0x1bbc4635'u32, 0x9e81032d'u32, 0x2701f50c'u32, 0x99847ab4'u32, 0xa0e3df79'u32, 0xba6cf38c'u32,
    0x10843094'u32, 0x2537a95e'u32, 0xf46f6ffe'u32, 0xa1ff3b1f'u32, 0x208cfb6a'u32, 0x8f458c74'u32, 0xd9e0a227'u32, 0x4ec73a34'u32,
    0xfc884f69'u32, 0x3e4de8df'u32, 0xef0e0088'u32, 0x3559648d'u32, 0x8a45388c'u32, 0x1d804366'u32, 0x721d9bfd'u32, 0xa58684bb'u32,
    0xe8256333'u32, 0x844e8212'u32, 0x128d8098'u32, 0xfed33fb4'u32, 0xce280ae1'u32, 0x27e19ba5'u32, 0xd5a6c252'u32, 0xe49754bd'u32,
    0xc5d655dd'u32, 0xeb667064'u32, 0x77840b4d'u32, 0xa1b6a801'u32, 0x84db26a9'u32, 0xe0b56714'u32, 0x21f043b7'u32, 0xe5d05860'u32,
    0x54f03084'u32, 0x066ff472'u32, 0xa31aa153'u32, 0xdadc4755'u32, 0xb5625dbf'u32, 0x68561be6'u32, 0x83ca6b94'u32, 0x2d6ed23b'u32,
    0xeccf01db'u32, 0xa6d3d0ba'u32, 0xb6803d5c'u32, 0xaf77a709'u32, 0x33b4a34c'u32, 0x397bc8d6'u32, 0x5ee22b95'u32, 0x5f0e5304'u32,
    0x81ed6f61'u32, 0x20e74364'u32, 0xb45e1378'u32, 0xde18639b'u32, 0x881ca122'u32, 0xb96726d1'u32, 0x8049a7e8'u32, 0x22b7da7b'u32,
    0x5e552d25'u32, 0x5272d237'u32, 0x79d2951c'u32, 0xc60d894c'u32, 0x488cb402'u32, 0x1ba4fe5b'u32, 0xa4b09f6b'u32, 0x1ca815cf'u32,
    0xa20c3005'u32, 0x8871df63'u32, 0xb9de2fcb'u32, 0x0cc6c9e9'u32, 0x0beeff53'u32, 0xe3214517'u32, 0xb4542835'u32, 0x9f63293c'u32,
    0xee41e729'u32, 0x6e1d2d7c'u32, 0x50045286'u32, 0x1e6685f3'u32, 0xf33401c6'u32, 0x30a22c95'u32, 0x31a70850'u32, 0x60930f13'u32,
    0x73f98417'u32, 0xa1269859'u32, 0xec645c44'u32, 0x52c877a9'u32, 0xcdff33a6'u32, 0xa02b1741'u32, 0x7cbad9a2'u32, 0x2180036f'u32,
    0x50d99c08'u32, 0xcb3f4861'u32, 0xc26bd765'u32, 0x64a3f6ab'u32, 0x80342676'u32, 0x25a75e7b'u32, 0xe4e6d1fc'u32, 0x20c710e6'u32,
    0xcdf0b680'u32, 0x17844d3b'u32, 0x31eef84d'u32, 0x7e0824e4'u32, 0x2ccb49eb'u32, 0x846a3bae'u32, 0x8ff77888'u32, 0xee5d60f6'u32,
    0x7af75673'u32, 0x2fdd5cdb'u32, 0xa11631c1'u32, 0x30f66f43'u32, 0xb3faec54'u32, 0x157fd7fa'u32, 0xef8579cc'u32, 0xd152de58'u32,
    0xdb2ffd5e'u32, 0x8f32ce19'u32, 0x306af97a'u32, 0x02f03ef8'u32, 0x99319ad5'u32, 0xc242fa0f'u32, 0xa7e3ebb0'u32, 0xc68e4906'u32,
    0xb8da230c'u32, 0x80823028'u32, 0xdcdef3c8'u32, 0xd35fb171'u32, 0x088a1bc8'u32, 0xbec0c560'u32, 0x61a3c9e8'u32, 0xbca8f54d'u32,
    0xc72feffa'u32, 0x22822e99'u32, 0x82c570b4'u32, 0xd8d94e89'u32, 0x8b1c34bc'u32, 0x301e16e6'u32, 0x273be979'u32, 0xb0ffeaa6'u32,
    0x61d9b8c6'u32, 0x00b24869'u32, 0xb7ffce3f'u32, 0x08dc283b'u32, 0x43daf65a'u32, 0xf7e19798'u32, 0x7619b72f'u32, 0x8f1c9ba4'u32,
    0xdc8637a0'u32, 0x16a7d3b1'u32, 0x9fc393b7'u32, 0xa7136eeb'u32, 0xc6bcc63e'u32, 0x1a513742'u32, 0xef6828bc'u32, 0x520365d6'u32,
    0x2d6a77ab'u32, 0x3527ed4b'u32, 0x821fd216'u32, 0x095c6e2e'u32, 0xdb92f2fb'u32, 0x5eea29cb'u32, 0x145892f5'u32, 0x91584f7f'u32,
    0x5483697b'u32, 0x2667a8cc'u32, 0x85196048'u32, 0x8c4bacea'u32, 0x833860d4'u32, 0x0d23e0f9'u32, 0x6c387e8a'u32, 0x0ae6d249'u32,
    0xb284600c'u32, 0xd835731d'u32, 0xdcb1c647'u32, 0xac4c56ea'u32, 0x3ebd81b3'u32, 0x230eabb0'u32, 0x6438bc87'u32, 0xf0b5b1fa'u32,
    0x8f5ea2b3'u32, 0xfc184642'u32, 0x0a036b7a'u32, 0x4fb089bd'u32, 0x649da589'u32, 0xa345415e'u32, 0x5c038323'u32, 0x3e5d3bb9'u32,
    0x43d79572'u32, 0x7e6dd07c'u32, 0x06dfdf1e'u32, 0x6c6cc4ef'u32, 0x7160a539'u32, 0x73bfbe70'u32, 0x83877605'u32, 0x4523ecf1'u32
  ]
  SBox3*: array[256, uint32] = [
    0x8defc240'u32, 0x25fa5d9f'u32, 0xeb903dbf'u32, 0xe810c907'u32, 0x47607fff'u32, 0x369fe44b'u32, 0x8c1fc644'u32, 0xaececa90'u32,
    0xbeb1f9bf'u32, 0xeefbcaea'u32, 0xe8cf1950'u32, 0x51df07ae'u32, 0x920e8806'u32, 0xf0ad0548'u32, 0xe13c8d83'u32, 0x927010d5'u32,
    0x11107d9f'u32, 0x07647db9'u32, 0xb2e3e4d4'u32, 0x3d4f285e'u32, 0xb9afa820'u32, 0xfade82e0'u32, 0xa067268b'u32, 0x8272792e'u32,
    0x553fb2c0'u32, 0x489ae22b'u32, 0xd4ef9794'u32, 0x125e3fbc'u32, 0x21fffcee'u32, 0x825b1bfd'u32, 0x9255c5ed'u32, 0x1257a240'u32,
    0x4e1a8302'u32, 0xbae07fff'u32, 0x528246e7'u32, 0x8e57140e'u32, 0x3373f7bf'u32, 0x8c9f8188'u32, 0xa6fc4ee8'u32, 0xc982b5a5'u32,
    0xa8c01db7'u32, 0x579fc264'u32, 0x67094f31'u32, 0xf2bd3f5f'u32, 0x40fff7c1'u32, 0x1fb78dfc'u32, 0x8e6bd2c1'u32, 0x437be59b'u32,
    0x99b03dbf'u32, 0xb5dbc64b'u32, 0x638dc0e6'u32, 0x55819d99'u32, 0xa197c81c'u32, 0x4a012d6e'u32, 0xc5884a28'u32, 0xccc36f71'u32,
    0xb843c213'u32, 0x6c0743f1'u32, 0x8309893c'u32, 0x0feddd5f'u32, 0x2f7fe850'u32, 0xd7c07f7e'u32, 0x02507fbf'u32, 0x5afb9a04'u32,
    0xa747d2d0'u32, 0x1651192e'u32, 0xaf70bf3e'u32, 0x58c31380'u32, 0x5f98302e'u32, 0x727cc3c4'u32, 0x0a0fb402'u32, 0x0f7fef82'u32,
    0x8c96fdad'u32, 0x5d2c2aae'u32, 0x8ee99a49'u32, 0x50da88b8'u32, 0x8427f4a0'u32, 0x1eac5790'u32, 0x796fb449'u32, 0x8252dc15'u32,
    0xefbd7d9b'u32, 0xa672597d'u32, 0xada840d8'u32, 0x45f54504'u32, 0xfa5d7403'u32, 0xe83ec305'u32, 0x4f91751a'u32, 0x925669c2'u32,
    0x23efe941'u32, 0xa903f12e'u32, 0x60270df2'u32, 0x0276e4b6'u32, 0x94fd6574'u32, 0x927985b2'u32, 0x8276dbcb'u32, 0x02778176'u32,
    0xf8af918d'u32, 0x4e48f79e'u32, 0x8f616ddf'u32, 0xe29d840e'u32, 0x842f7d83'u32, 0x340ce5c8'u32, 0x96bbb682'u32, 0x93b4b148'u32,
    0xef303cab'u32, 0x984faf28'u32, 0x779faf9b'u32, 0x92dc560d'u32, 0x224d1e20'u32, 0x8437aa88'u32, 0x7d29dc96'u32, 0x2756d3dc'u32,
    0x8b907cee'u32, 0xb51fd240'u32, 0xe7c07ce3'u32, 0xe566b4a1'u32, 0xc3e9615e'u32, 0x3cf8209d'u32, 0x6094d1e3'u32, 0xcd9ca341'u32,
    0x5c76460e'u32, 0x00ea983b'u32, 0xd4d67881'u32, 0xfd47572c'u32, 0xf76cedd9'u32, 0xbda8229c'u32, 0x127dadaa'u32, 0x438a074e'u32,
    0x1f97c090'u32, 0x081bdb8a'u32, 0x93a07ebe'u32, 0xb938ca15'u32, 0x97b03cff'u32, 0x3dc2c0f8'u32, 0x8d1ab2ec'u32, 0x64380e51'u32,
    0x68cc7bfb'u32, 0xd90f2788'u32, 0x12490181'u32, 0x5de5ffd4'u32, 0xdd7ef86a'u32, 0x76a2e214'u32, 0xb9a40368'u32, 0x925d958f'u32,
    0x4b39fffa'u32, 0xba39aee9'u32, 0xa4ffd30b'u32, 0xfaf7933b'u32, 0x6d498623'u32, 0x193cbcfa'u32, 0x27627545'u32, 0x825cf47a'u32,
    0x61bd8ba0'u32, 0xd11e42d1'u32, 0xcead04f4'u32, 0x127ea392'u32, 0x10428db7'u32, 0x8272a972'u32, 0x9270c4a8'u32, 0x127de50b'u32,
    0x285ba1c8'u32, 0x3c62f44f'u32, 0x35c0eaa5'u32, 0xe805d231'u32, 0x428929fb'u32, 0xb4fcdf82'u32, 0x4fb66a53'u32, 0x0e7dc15b'u32,
    0x1f081fab'u32, 0x108618ae'u32, 0xfcfd086d'u32, 0xf9ff2889'u32, 0x694bcc11'u32, 0x236a5cae'u32, 0x12deca4d'u32, 0x2c3f8cc5'u32,
    0xd2d02dfe'u32, 0xf8ef5896'u32, 0xe4cf52da'u32, 0x95155b67'u32, 0x494a488c'u32, 0xb9b6a80c'u32, 0x5c8f82bc'u32, 0x89d36b45'u32,
    0x3a609437'u32, 0xec00c9a9'u32, 0x44715253'u32, 0x0a874b49'u32, 0xd773bc40'u32, 0x7c34671c'u32, 0x02717ef6'u32, 0x4feb5536'u32,
    0xa2d02fff'u32, 0xd2bf60c4'u32, 0xd43f03c0'u32, 0x50b4ef6d'u32, 0x07478cd1'u32, 0x006e1888'u32, 0xa2e53f55'u32, 0xb9e6d4bc'u32,
    0xa2048016'u32, 0x97573833'u32, 0xd7207d67'u32, 0xde0f8f3d'u32, 0x72f87b33'u32, 0xabcc4f33'u32, 0x7688c55d'u32, 0x7b00a6b0'u32,
    0x947b0001'u32, 0x570075d2'u32, 0xf9bb88f8'u32, 0x8942019e'u32, 0x4264a5ff'u32, 0x856302e0'u32, 0x72dbd92b'u32, 0xee971b69'u32,
    0x6ea22fde'u32, 0x5f08ae2b'u32, 0xaf7a616d'u32, 0xe5c98767'u32, 0xcf1febd2'u32, 0x61efc8c2'u32, 0xf1ac2571'u32, 0xcc8239c2'u32,
    0x67214cb8'u32, 0xb1e583d1'u32, 0xb7dc3e62'u32, 0x7f10bdce'u32, 0xf90a5c38'u32, 0x0ff0443d'u32, 0x606e6dc6'u32, 0x60543a49'u32,
    0x5727c148'u32, 0x2be98a1d'u32, 0x8ab41738'u32, 0x20e1be24'u32, 0xaf96da0f'u32, 0x68458425'u32, 0x99833be5'u32, 0x600d457d'u32,
    0x282f9350'u32, 0x8334b362'u32, 0xd91d1120'u32, 0x2b6d8da0'u32, 0x642b1e31'u32, 0x9c305a00'u32, 0x52bce688'u32, 0x1b03588a'u32,
    0xf7baefd5'u32, 0x4142ed9c'u32, 0xa4315c11'u32, 0x83323ec5'u32, 0xdfef4636'u32, 0xa133c501'u32, 0xe9d3531c'u32, 0xee353783'u32
  ]
  SBox4*: array[256, uint32] = [
    0x9db30420'u32, 0x1fb6e9de'u32, 0xa7be7bef'u32, 0xd273a298'u32, 0x4a4f7bdb'u32, 0x64ad8c57'u32, 0x85510443'u32, 0xfa020ed1'u32,
    0x7e287aff'u32, 0xe60fb663'u32, 0x095f35a1'u32, 0x79ebf120'u32, 0xfd059d43'u32, 0x6497b7b1'u32, 0xf3641f63'u32, 0x241e4adf'u32,
    0x28147f5f'u32, 0x4fa2b8cd'u32, 0xc9430040'u32, 0x0cc32220'u32, 0xfdd30b30'u32, 0xc0a5374f'u32, 0x1d2d00d9'u32, 0x24147b15'u32,
    0xee4d111a'u32, 0x0fca5167'u32, 0x71ff904c'u32, 0x2d195ffe'u32, 0x1a05645f'u32, 0x0c13fefe'u32, 0x081b08ca'u32, 0x05170121'u32,
    0x80530100'u32, 0xe83e5efe'u32, 0xac9af4f8'u32, 0x7fe72701'u32, 0xd2b8ee5f'u32, 0x06df4261'u32, 0xbb9e9b8a'u32, 0x7293ea25'u32,
    0xce84ffdf'u32, 0xf5718801'u32, 0x3dd64b04'u32, 0xa26f263b'u32, 0x7ed48400'u32, 0x547eebe6'u32, 0x446d4ca0'u32, 0x6cf3d6f5'u32,
    0x2649abdf'u32, 0xaea0c7f5'u32, 0x36338cc1'u32, 0x503f7e93'u32, 0xd3772061'u32, 0x11b638e1'u32, 0x72500e03'u32, 0xf80eb2bb'u32,
    0xabe0502e'u32, 0xec8d77de'u32, 0x57971e81'u32, 0xe14f6746'u32, 0xc9335400'u32, 0x6920318f'u32, 0x081dbb99'u32, 0xffc304a5'u32,
    0x4d351805'u32, 0x7f3d5ce3'u32, 0xa6c866c6'u32, 0x5d5bcca9'u32, 0xdaec6fea'u32, 0x9f926f91'u32, 0x9f46222f'u32, 0x3991467d'u32,
    0xa5bf6d8e'u32, 0x1143c44f'u32, 0x43958302'u32, 0xd0214eeb'u32, 0x022083b8'u32, 0x3fb6180c'u32, 0x18f8931e'u32, 0x281658e6'u32,
    0x26486e3e'u32, 0x8bd78a70'u32, 0x7477e4c1'u32, 0xb506e07c'u32, 0xf32d0a25'u32, 0x79098b02'u32, 0xe4eabb81'u32, 0x28123b23'u32,
    0x69dead38'u32, 0x1574ca16'u32, 0xdf871b62'u32, 0x211c40b7'u32, 0xa51a9ef9'u32, 0x0014377b'u32, 0x041e8ac8'u32, 0x09114003'u32,
    0xbd59e4d2'u32, 0xe3d156d5'u32, 0x4fe876d5'u32, 0x2f91a340'u32, 0x557be8de'u32, 0x00eae4a7'u32, 0x0ce5c2ec'u32, 0x4db4bba6'u32,
    0xe756bdff'u32, 0xdd3369ac'u32, 0xec17b035'u32, 0x06572327'u32, 0x99afc8b0'u32, 0x56c8c391'u32, 0x6b65811c'u32, 0x5e146119'u32,
    0x6e85cb75'u32, 0xbe07c002'u32, 0xc2325577'u32, 0x893ff4ec'u32, 0x5bbfc92d'u32, 0xd0ec3b25'u32, 0xb7801ab7'u32, 0x8d6d3b24'u32,
    0x20c763ef'u32, 0xc366a5fc'u32, 0x9c382880'u32, 0x0ace3205'u32, 0xaac9548a'u32, 0xeca1d7c7'u32, 0x041afa32'u32, 0x1d16625a'u32,
    0x6701902c'u32, 0x9b757a54'u32, 0x31d477f7'u32, 0x9126b031'u32, 0x36cc6fdb'u32, 0xc70b8b46'u32, 0xd9e66a48'u32, 0x56e55a79'u32,
    0x026a4ceb'u32, 0x52437eff'u32, 0x2f8f76b4'u32, 0x0df980a5'u32, 0x8674cde3'u32, 0xedda04eb'u32, 0x17a9be04'u32, 0x2c18f4df'u32,
    0xb7747f9d'u32, 0xab2af7b4'u32, 0xefc34d20'u32, 0x2e096b7c'u32, 0x1741a254'u32, 0xe5b6a035'u32, 0x213d42f6'u32, 0x2c1c7c26'u32,
    0x61c2f50f'u32, 0x6552daf9'u32, 0xd2c231f8'u32, 0x25130f69'u32, 0xd8167fa2'u32, 0x0418f2c8'u32, 0x001a96a6'u32, 0x0d1526ab'u32,
    0x63315c21'u32, 0x5e0a72ec'u32, 0x49bafefd'u32, 0x187908d9'u32, 0x8d0dbd86'u32, 0x311170a7'u32, 0x3e9b640c'u32, 0xcc3e10d7'u32,
    0xd5cad3b6'u32, 0x0caec388'u32, 0xf73001e1'u32, 0x6c728aff'u32, 0x71eae2a1'u32, 0x1f9af36e'u32, 0xcfcbd12f'u32, 0xc1de8417'u32,
    0xac07be6b'u32, 0xcb44a1d8'u32, 0x8b9b0f56'u32, 0x013988c3'u32, 0xb1c52fca'u32, 0xb4be31cd'u32, 0xd8782806'u32, 0x12a3a4e2'u32,
    0x6f7de532'u32, 0x58fd7eb6'u32, 0xd01ee900'u32, 0x24adffc2'u32, 0xf4990fc5'u32, 0x9711aac5'u32, 0x001d7b95'u32, 0x82e5e7d2'u32,
    0x109873f6'u32, 0x00613096'u32, 0xc32d9521'u32, 0xada121ff'u32, 0x29908415'u32, 0x7fbb977f'u32, 0xaf9eb3db'u32, 0x29c9ed2a'u32,
    0x5ce2a465'u32, 0xa730f32c'u32, 0xd0aa3fe8'u32, 0x8a5cc091'u32, 0xd49e2ce7'u32, 0x0ce454a9'u32, 0xd60acd86'u32, 0x015f1919'u32,
    0x77079103'u32, 0xdea03af6'u32, 0x78a8565e'u32, 0xdee356df'u32, 0x21f05cbe'u32, 0x8b75e387'u32, 0xb3c50651'u32, 0xb8a5c3ef'u32,
    0xd8eeb6d2'u32, 0xe523be77'u32, 0xc2154529'u32, 0x2f69efdf'u32, 0xafe67afb'u32, 0xf470c4b2'u32, 0xf3e0eb5b'u32, 0xd6cc9876'u32,
    0x39e4460c'u32, 0x1fda8538'u32, 0x1987832f'u32, 0xca007367'u32, 0xa99144f8'u32, 0x296b299e'u32, 0x492fc295'u32, 0x9266beab'u32,
    0xb5676e69'u32, 0x9bd3ddda'u32, 0xdf7e052f'u32, 0xdb25701c'u32, 0x1b5e51ee'u32, 0xf65324e6'u32, 0x6afce36c'u32, 0x0316cc04'u32,
    0x8644213e'u32, 0xb7dc59d0'u32, 0x7965291f'u32, 0xccd6fd43'u32, 0x41823979'u32, 0x932bcdf6'u32, 0xb657c34d'u32, 0x4edfd282'u32,
    0x7ae5290c'u32, 0x3cb9536b'u32, 0x851e20fe'u32, 0x9833557e'u32, 0x13ecf0b0'u32, 0xd3ffb372'u32, 0x3f85c5c1'u32, 0x0aef7ed2'u32
  ]
  SBox5*: array[256, uint32] = [
    0x7ec90c04'u32, 0x2c6e74b9'u32, 0x9b0e66df'u32, 0xa6337911'u32, 0xb86a7fff'u32, 0x1dd358f5'u32, 0x44dd9d44'u32, 0x1731167f'u32,
    0x08fbf1fa'u32, 0xe7f511cc'u32, 0xd2051b00'u32, 0x735aba00'u32, 0x2ab722d8'u32, 0x386381cb'u32, 0xacf6243a'u32, 0x69befd7a'u32,
    0xe6a2e77f'u32, 0xf0c720cd'u32, 0xc4494816'u32, 0xccf5c180'u32, 0x38851640'u32, 0x15b0a848'u32, 0xe68b18cb'u32, 0x4caadeff'u32,
    0x5f480a01'u32, 0x0412b2aa'u32, 0x259814fc'u32, 0x41d0efe2'u32, 0x4e40b48d'u32, 0x248eb6fb'u32, 0x8dba1cfe'u32, 0x41a99b02'u32,
    0x1a550a04'u32, 0xba8f65cb'u32, 0x7251f4e7'u32, 0x95a51725'u32, 0xc106ecd7'u32, 0x97a5980a'u32, 0xc539b9aa'u32, 0x4d79fe6a'u32,
    0xf2f3f763'u32, 0x68af8040'u32, 0xed0c9e56'u32, 0x11b4958b'u32, 0xe1eb5a88'u32, 0x8709e6b0'u32, 0xd7e07156'u32, 0x4e29fea7'u32,
    0x6366e52d'u32, 0x02d1c000'u32, 0xc4ac8e05'u32, 0x9377f571'u32, 0x0c05372a'u32, 0x578535f2'u32, 0x2261be02'u32, 0xd642a0c9'u32,
    0xdf13a280'u32, 0x74b55bd2'u32, 0x682199c0'u32, 0xd421e5ec'u32, 0x53fb3ce8'u32, 0xc8adedb3'u32, 0x28a87fc9'u32, 0x3d959981'u32,
    0x5c1ff900'u32, 0xfe38d399'u32, 0x0c4eff0b'u32, 0x062407ea'u32, 0xaa2f4fb1'u32, 0x4fb96976'u32, 0x90c79505'u32, 0xb0a8a774'u32,
    0xef55a1ff'u32, 0xe59ca2c2'u32, 0xa6b62d27'u32, 0xe66a4263'u32, 0xdf65001f'u32, 0x0ec50966'u32, 0xdfdd55bc'u32, 0x29de0655'u32,
    0x911e739a'u32, 0x17af8975'u32, 0x32c7911c'u32, 0x89f89468'u32, 0x0d01e980'u32, 0x524755f4'u32, 0x03b63cc9'u32, 0x0cc844b2'u32,
    0xbcf3f0aa'u32, 0x87ac36e9'u32, 0xe53a7426'u32, 0x01b3d82b'u32, 0x1a9e7449'u32, 0x64ee2d7e'u32, 0xcddbb1da'u32, 0x01c94910'u32,
    0xb868bf80'u32, 0x0d26f3fd'u32, 0x9342ede7'u32, 0x04a5c284'u32, 0x636737b6'u32, 0x50f5b616'u32, 0xf24766e3'u32, 0x8eca36c1'u32,
    0x136e05db'u32, 0xfef18391'u32, 0xfb887a37'u32, 0xd6e7f7d4'u32, 0xc7fb7dc9'u32, 0x3063fcdf'u32, 0xb6f589de'u32, 0xec2941da'u32,
    0x26e46695'u32, 0xb7566419'u32, 0xf654efc5'u32, 0xd08d58b7'u32, 0x48925401'u32, 0xc1bacb7f'u32, 0xe5ff550f'u32, 0xb6083049'u32,
    0x5bb5d0e8'u32, 0x87d72e5a'u32, 0xab6a6ee1'u32, 0x223a66ce'u32, 0xc62bf3cd'u32, 0x9e0885f9'u32, 0x68cb3e47'u32, 0x086c010f'u32,
    0xa21de820'u32, 0xd18b69de'u32, 0xf3f65777'u32, 0xfa02c3f6'u32, 0x407edac3'u32, 0xcbb3d550'u32, 0x1793084d'u32, 0xb0d70eba'u32,
    0x0ab378d5'u32, 0xd951fb0c'u32, 0xded7da56'u32, 0x4124bbe4'u32, 0x94ca0b56'u32, 0x0f5755d1'u32, 0xe0e1e56e'u32, 0x6184b5be'u32,
    0x580a249f'u32, 0x94f74bc0'u32, 0xe327888e'u32, 0x9f7b5561'u32, 0xc3dc0280'u32, 0x05687715'u32, 0x646c6bd7'u32, 0x44904db3'u32,
    0x66b4f0a3'u32, 0xc0f1648a'u32, 0x697ed5af'u32, 0x49e92ff6'u32, 0x309e374f'u32, 0x2cb6356a'u32, 0x85808573'u32, 0x4991f840'u32,
    0x76f0ae02'u32, 0x083be84d'u32, 0x28421c9a'u32, 0x44489406'u32, 0x736e4cb8'u32, 0xc1092910'u32, 0x8bc95fc6'u32, 0x7d869cf4'u32,
    0x134f616f'u32, 0x2e77118d'u32, 0xb31b2be1'u32, 0xaa90b472'u32, 0x3ca5d717'u32, 0x7d161bba'u32, 0x9cad9010'u32, 0xaf462ba2'u32,
    0x9fe459d2'u32, 0x45d34559'u32, 0xd9f2da13'u32, 0xdbc65487'u32, 0xf3e4f94e'u32, 0x176d486f'u32, 0x097c13ea'u32, 0x631da5c7'u32,
    0x445f7382'u32, 0x175683f4'u32, 0xcdc66a97'u32, 0x70be0288'u32, 0xb3cdcf72'u32, 0x6e5dd2f3'u32, 0x20936079'u32, 0x459b80a5'u32,
    0xbe60e2db'u32, 0xa9c23101'u32, 0xeba5315c'u32, 0x224e42f2'u32, 0x1c5c1572'u32, 0xf6721b2c'u32, 0x1ad2fff3'u32, 0x8c25404e'u32,
    0x324ed72f'u32, 0x4067b7fd'u32, 0x0523138e'u32, 0x5ca3bc78'u32, 0xdc0fd66e'u32, 0x75922283'u32, 0x784d6b17'u32, 0x58ebb16e'u32,
    0x44094f85'u32, 0x3f481d87'u32, 0xfcfeae7b'u32, 0x77b5ff76'u32, 0x8c2302bf'u32, 0xaaf47556'u32, 0x5f46b02a'u32, 0x2b092801'u32,
    0x3d38f5f7'u32, 0x0ca81f36'u32, 0x52af4a8a'u32, 0x66d5e7c0'u32, 0xdf3b0874'u32, 0x95055110'u32, 0x1b5ad7a8'u32, 0xf61ed5ad'u32,
    0x6cf6e479'u32, 0x20758184'u32, 0xd0cefa65'u32, 0x88f7be58'u32, 0x4a046826'u32, 0x0ff6f8f3'u32, 0xa09c7f70'u32, 0x5346aba0'u32,
    0x5ce96c28'u32, 0xe176eda3'u32, 0x6bac307f'u32, 0x376829d2'u32, 0x85360fa9'u32, 0x17e3fe2a'u32, 0x24b79767'u32, 0xf5a96b20'u32,
    0xd6cd2595'u32, 0x68ff1ebf'u32, 0x7555442c'u32, 0xf19f06be'u32, 0xf9e0659a'u32, 0xeeb9491d'u32, 0x34010718'u32, 0xbb30cab8'u32,
    0xe822fe15'u32, 0x88570983'u32, 0x750e6249'u32, 0xda627e55'u32, 0x5e76ffa8'u32, 0xb1534546'u32, 0x6d47de08'u32, 0xefe9e7d4'u32
  ]
  SBox6*: array[256, uint32] = [
    0xf6fa8f9d'u32, 0x2cac6ce1'u32, 0x4ca34867'u32, 0xe2337f7c'u32, 0x95db08e7'u32, 0x016843b4'u32, 0xeced5cbc'u32, 0x325553ac'u32,
    0xbf9f0960'u32, 0xdfa1e2ed'u32, 0x83f0579d'u32, 0x63ed86b9'u32, 0x1ab6a6b8'u32, 0xde5ebe39'u32, 0xf38ff732'u32, 0x8989b138'u32,
    0x33f14961'u32, 0xc01937bd'u32, 0xf506c6da'u32, 0xe4625e7e'u32, 0xa308ea99'u32, 0x4e23e33c'u32, 0x79cbd7cc'u32, 0x48a14367'u32,
    0xa3149619'u32, 0xfec94bd5'u32, 0xa114174a'u32, 0xeaa01866'u32, 0xa084db2d'u32, 0x09a8486f'u32, 0xa888614a'u32, 0x2900af98'u32,
    0x01665991'u32, 0xe1992863'u32, 0xc8f30c60'u32, 0x2e78ef3c'u32, 0xd0d51932'u32, 0xcf0fec14'u32, 0xf7ca07d2'u32, 0xd0a82072'u32,
    0xfd41197e'u32, 0x9305a6b0'u32, 0xe86be3da'u32, 0x74bed3cd'u32, 0x372da53c'u32, 0x4c7f4448'u32, 0xdab5d440'u32, 0x6dba0ec3'u32,
    0x083919a7'u32, 0x9fbaeed9'u32, 0x49dbcfb0'u32, 0x4e670c53'u32, 0x5c3d9c01'u32, 0x64bdb941'u32, 0x2c0e636a'u32, 0xba7dd9cd'u32,
    0xea6f7388'u32, 0xe70bc762'u32, 0x35f29adb'u32, 0x5c4cdd8d'u32, 0xf0d48d8c'u32, 0xb88153e2'u32, 0x08a19866'u32, 0x1ae2eac8'u32,
    0x284caf89'u32, 0xaa928223'u32, 0x9334be53'u32, 0x3b3a21bf'u32, 0x16434be3'u32, 0x9aea3906'u32, 0xefe8c36e'u32, 0xf890cdd9'u32,
    0x80226dae'u32, 0xc340a4a3'u32, 0xdf7e9c09'u32, 0xa694a807'u32, 0x5b7c5ecc'u32, 0x221db3a6'u32, 0x9a69a02f'u32, 0x68818a54'u32,
    0xceb2296f'u32, 0x53c0843a'u32, 0xfe893655'u32, 0x25bfe68a'u32, 0xb4628abc'u32, 0xcf222ebf'u32, 0x25ac6f48'u32, 0xa9a99387'u32,
    0x53bddb65'u32, 0xe76ffbe7'u32, 0xe967fd78'u32, 0x0ba93563'u32, 0x8e342bc1'u32, 0xe8a11be9'u32, 0x4980740d'u32, 0xc8087dfc'u32,
    0x8de4bf99'u32, 0xa11101a0'u32, 0x7fd37975'u32, 0xda5a26c0'u32, 0xe81f994f'u32, 0x9528cd89'u32, 0xfd339fed'u32, 0xb87834bf'u32,
    0x5f04456d'u32, 0x22258698'u32, 0xc9c4c83b'u32, 0x2dc156be'u32, 0x4f628daa'u32, 0x57f55ec5'u32, 0xe2220abe'u32, 0xd2916ebf'u32,
    0x4ec75b95'u32, 0x24f2c3c0'u32, 0x42d15d99'u32, 0xcd0d7fa0'u32, 0x7b6e27ff'u32, 0xa8dc8af0'u32, 0x7345c106'u32, 0xf41e232f'u32,
    0x35162386'u32, 0xe6ea8926'u32, 0x3333b094'u32, 0x157ec6f2'u32, 0x372b74af'u32, 0x692573e4'u32, 0xe9a9d848'u32, 0xf3160289'u32,
    0x3a62ef1d'u32, 0xa787e238'u32, 0xf3a5f676'u32, 0x74364853'u32, 0x20951063'u32, 0x4576698d'u32, 0xb6fad407'u32, 0x592af950'u32,
    0x36f73523'u32, 0x4cfb6e87'u32, 0x7da4cec0'u32, 0x6c152daa'u32, 0xcb0396a8'u32, 0xc50dfe5d'u32, 0xfcd707ab'u32, 0x0921c42f'u32,
    0x89dff0bb'u32, 0x5fe2be78'u32, 0x448f4f33'u32, 0x754613c9'u32, 0x2b05d08d'u32, 0x48b9d585'u32, 0xdc049441'u32, 0xc8098f9b'u32,
    0x7dede786'u32, 0xc39a3373'u32, 0x42410005'u32, 0x6a091751'u32, 0x0ef3c8a6'u32, 0x890072d6'u32, 0x28207682'u32, 0xa9a9f7be'u32,
    0xbf32679d'u32, 0xd45b5b75'u32, 0xb353fd00'u32, 0xcbb0e358'u32, 0x830f220a'u32, 0x1f8fb214'u32, 0xd372cf08'u32, 0xcc3c4a13'u32,
    0x8cf63166'u32, 0x061c87be'u32, 0x88c98f88'u32, 0x6062e397'u32, 0x47cf8e7a'u32, 0xb6c85283'u32, 0x3cc2acfb'u32, 0x3fc06976'u32,
    0x4e8f0252'u32, 0x64d8314d'u32, 0xda3870e3'u32, 0x1e665459'u32, 0xc10908f0'u32, 0x513021a5'u32, 0x6c5b68b7'u32, 0x822f8aa0'u32,
    0x3007cd3e'u32, 0x74719eef'u32, 0xdc872681'u32, 0x073340d4'u32, 0x7e432fd9'u32, 0x0c5ec241'u32, 0x8809286c'u32, 0xf592d891'u32,
    0x08a930f6'u32, 0x957ef305'u32, 0xb7fbffbd'u32, 0xc266e96f'u32, 0x6fe4ac98'u32, 0xb173ecc0'u32, 0xbc60b42a'u32, 0x953498da'u32,
    0xfba1ae12'u32, 0x2d4bd736'u32, 0x0f25faab'u32, 0xa4f3fceb'u32, 0xe2969123'u32, 0x257f0c3d'u32, 0x9348af49'u32, 0x361400bc'u32,
    0xe8816f4a'u32, 0x3814f200'u32, 0xa3f94043'u32, 0x9c7a54c2'u32, 0xbc704f57'u32, 0xda41e7f9'u32, 0xc25ad33a'u32, 0x54f4a084'u32,
    0xb17f5505'u32, 0x59357cbe'u32, 0xedbd15c8'u32, 0x7f97c5ab'u32, 0xba5ac7b5'u32, 0xb6f6deaf'u32, 0x3a479c3a'u32, 0x5302da25'u32,
    0x653d7e6a'u32, 0x54268d49'u32, 0x51a477ea'u32, 0x5017d55b'u32, 0xd7d25d88'u32, 0x44136c76'u32, 0x0404a8c8'u32, 0xb8e5a121'u32,
    0xb81a928a'u32, 0x60ed5869'u32, 0x97c55b96'u32, 0xeaec991b'u32, 0x29935913'u32, 0x01fdb7f1'u32, 0x088e8dfa'u32, 0x9ab6f6f5'u32,
    0x3b4cbf9f'u32, 0x4a5de3ab'u32, 0xe6051d35'u32, 0xa0e1d855'u32, 0xd36b4cf1'u32, 0xf544edeb'u32, 0xb0e93524'u32, 0xbebb8fbd'u32,
    0xa2d762cf'u32, 0x49c92f54'u32, 0x38b5f331'u32, 0x7128a454'u32, 0x48392905'u32, 0xa65b1db8'u32, 0x851c97bd'u32, 0xd675cf2f'u32
  ]
  SBox7*: array[256, uint32] = [
    0x85e04019'u32, 0x332bf567'u32, 0x662dbfff'u32, 0xcfc65693'u32, 0x2a8d7f6f'u32, 0xab9bc912'u32, 0xde6008a1'u32, 0x2028da1f'u32,
    0x0227bce7'u32, 0x4d642916'u32, 0x18fac300'u32, 0x50f18b82'u32, 0x2cb2cb11'u32, 0xb232e75c'u32, 0x4b3695f2'u32, 0xb28707de'u32,
    0xa05fbcf6'u32, 0xcd4181e9'u32, 0xe150210c'u32, 0xe24ef1bd'u32, 0xb168c381'u32, 0xfde4e789'u32, 0x5c79b0d8'u32, 0x1e8bfd43'u32,
    0x4d495001'u32, 0x38be4341'u32, 0x913cee1d'u32, 0x92a79c3f'u32, 0x089766be'u32, 0xbaeeadf4'u32, 0x1286becf'u32, 0xb6eacb19'u32,
    0x2660c200'u32, 0x7565bde4'u32, 0x64241f7a'u32, 0x8248dca9'u32, 0xc3b3ad66'u32, 0x28136086'u32, 0x0bd8dfa8'u32, 0x356d1cf2'u32,
    0x107789be'u32, 0xb3b2e9ce'u32, 0x0502aa8f'u32, 0x0bc0351e'u32, 0x166bf52a'u32, 0xeb12ff82'u32, 0xe3486911'u32, 0xd34d7516'u32,
    0x4e7b3aff'u32, 0x5f43671b'u32, 0x9cf6e037'u32, 0x4981ac83'u32, 0x334266ce'u32, 0x8c9341b7'u32, 0xd0d854c0'u32, 0xcb3a6c88'u32,
    0x47bc2829'u32, 0x4725ba37'u32, 0xa66ad22b'u32, 0x7ad61f1e'u32, 0x0c5cbafa'u32, 0x4437f107'u32, 0xb6e79962'u32, 0x42d2d816'u32,
    0x0a961288'u32, 0xe1a5c06e'u32, 0x13749e67'u32, 0x72fc081a'u32, 0xb1d139f7'u32, 0xf9583745'u32, 0xcf19df58'u32, 0xbec3f756'u32,
    0xc06eba30'u32, 0x07211b24'u32, 0x45c28829'u32, 0xc95e317f'u32, 0xbc8ec511'u32, 0x38bc46e9'u32, 0xc6e6fa14'u32, 0xbae8584a'u32,
    0xad4ebc46'u32, 0x468f508b'u32, 0x7829435f'u32, 0xf124183b'u32, 0x821dba9f'u32, 0xaff60ff4'u32, 0xea2c4e6d'u32, 0x16e39264'u32,
    0x92544a8b'u32, 0x009b4fc3'u32, 0xaba68ced'u32, 0x9ac96f78'u32, 0x06a5b79a'u32, 0xb2856e6e'u32, 0x1aec3ca9'u32, 0xbe838688'u32,
    0x0e0804e9'u32, 0x55f1be56'u32, 0xe7e5363b'u32, 0xb3a1f25d'u32, 0xf7debb85'u32, 0x61fe033c'u32, 0x16746233'u32, 0x3c034c28'u32,
    0xda6d0c74'u32, 0x79aac56c'u32, 0x3ce4e1ad'u32, 0x51f0c802'u32, 0x98f8f35a'u32, 0x1626a49f'u32, 0xeed82b29'u32, 0x1d382fe3'u32,
    0x0c4fb99a'u32, 0xbb325778'u32, 0x3ec6d97b'u32, 0x6e77a6a9'u32, 0xcb658b5c'u32, 0xd45230c7'u32, 0x2bd1408b'u32, 0x60c03eb7'u32,
    0xb9068d78'u32, 0xa33754f4'u32, 0xf430c87d'u32, 0xc8a71302'u32, 0xb96d8c32'u32, 0xebd4e7be'u32, 0xbe8b9d2d'u32, 0x7979fb06'u32,
    0xe7225308'u32, 0x8b75cf77'u32, 0x11ef8da4'u32, 0xe083c858'u32, 0x8d6b786f'u32, 0x5a6317a6'u32, 0xfa5cf7a0'u32, 0x5dda0033'u32,
    0xf28ebfb0'u32, 0xf5b9c310'u32, 0xa0eac280'u32, 0x08b9767a'u32, 0xa3d9d2b0'u32, 0x79d34217'u32, 0x021a718d'u32, 0x9ac6336a'u32,
    0x2711fd60'u32, 0x438050e3'u32, 0x069908a8'u32, 0x3d7fedc4'u32, 0x826d2bef'u32, 0x4eeb8476'u32, 0x488dcf25'u32, 0x36c9d566'u32,
    0x28e74e41'u32, 0xc2610aca'u32, 0x3d49a9cf'u32, 0xbae3b9df'u32, 0xb65f8de6'u32, 0x92aeaf64'u32, 0x3ac7d5e6'u32, 0x9ea80509'u32,
    0xf22b017d'u32, 0xa4173f70'u32, 0xdd1e16c3'u32, 0x15e0d7f9'u32, 0x50b1b887'u32, 0x2b9f4fd5'u32, 0x625aba82'u32, 0x6a017962'u32,
    0x2ec01b9c'u32, 0x15488aa9'u32, 0xd716e740'u32, 0x40055a2c'u32, 0x93d29a22'u32, 0xe32dbf9a'u32, 0x058745b9'u32, 0x3453dc1e'u32,
    0xd699296e'u32, 0x496cff6f'u32, 0x1c9f4986'u32, 0xdfe2ed07'u32, 0xb87242d1'u32, 0x19de7eae'u32, 0x053e561a'u32, 0x15ad6f8c'u32,
    0x66626c1c'u32, 0x7154c24c'u32, 0xea082b2a'u32, 0x93eb2939'u32, 0x17dcb0f0'u32, 0x58d4f2ae'u32, 0x9ea294fb'u32, 0x52cf564c'u32,
    0x9883fe66'u32, 0x2ec40581'u32, 0x763953c3'u32, 0x01d6692e'u32, 0xd3a0c108'u32, 0xa1e7160e'u32, 0xe4f2dfa6'u32, 0x693ed285'u32,
    0x74904698'u32, 0x4c2b0edd'u32, 0x4f757656'u32, 0x5d393378'u32, 0xa132234f'u32, 0x3d321c5d'u32, 0xc3f5e194'u32, 0x4b269301'u32,
    0xc79f022f'u32, 0x3c997e7e'u32, 0x5e4f9504'u32, 0x3ffafbbd'u32, 0x76f7ad0e'u32, 0x296693f4'u32, 0x3d1fce6f'u32, 0xc61e45be'u32,
    0xd3b5ab34'u32, 0xf72bf9b7'u32, 0x1b0434c0'u32, 0x4e72b567'u32, 0x5592a33d'u32, 0xb5229301'u32, 0xcfd2a87f'u32, 0x60aeb767'u32,
    0x1814386b'u32, 0x30bcc33d'u32, 0x38a0c07d'u32, 0xfd1606f2'u32, 0xc363519b'u32, 0x589dd390'u32, 0x5479f8e6'u32, 0x1cb8d647'u32,
    0x97fd61a9'u32, 0xea7759f4'u32, 0x2d57539d'u32, 0x569a58cf'u32, 0xe84e63ad'u32, 0x462e1b78'u32, 0x6580f87e'u32, 0xf3817914'u32,
    0x91da55f4'u32, 0x40a230f3'u32, 0xd1988f35'u32, 0xb6e318d2'u32, 0x3ffa50bc'u32, 0x3d40f021'u32, 0xc3c0bdae'u32, 0x4958c24c'u32,
    0x518f36b2'u32, 0x84b1d370'u32, 0x0fedce83'u32, 0x878ddada'u32, 0xf2a279c7'u32, 0x94e01be8'u32, 0x90716f4b'u32, 0x954b8aa3'u32
  ]
  SBox8*: array[256, uint32] = [
    0xe216300d'u32, 0xbbddfffc'u32, 0xa7ebdabd'u32, 0x35648095'u32, 0x7789f8b7'u32, 0xe6c1121b'u32, 0x0e241600'u32, 0x052ce8b5'u32,
    0x11a9cfb0'u32, 0xe5952f11'u32, 0xece7990a'u32, 0x9386d174'u32, 0x2a42931c'u32, 0x76e38111'u32, 0xb12def3a'u32, 0x37ddddfc'u32,
    0xde9adeb1'u32, 0x0a0cc32c'u32, 0xbe197029'u32, 0x84a00940'u32, 0xbb243a0f'u32, 0xb4d137cf'u32, 0xb44e79f0'u32, 0x049eedfd'u32,
    0x0b15a15d'u32, 0x480d3168'u32, 0x8bbbde5a'u32, 0x669ded42'u32, 0xc7ece831'u32, 0x3f8f95e7'u32, 0x72df191b'u32, 0x7580330d'u32,
    0x94074251'u32, 0x5c7dcdfa'u32, 0xabbe6d63'u32, 0xaa402164'u32, 0xb301d40a'u32, 0x02e7d1ca'u32, 0x53571dae'u32, 0x7a3182a2'u32,
    0x12a8ddec'u32, 0xfdaa335d'u32, 0x176f43e8'u32, 0x71fb46d4'u32, 0x38129022'u32, 0xce949ad4'u32, 0xb84769ad'u32, 0x965bd862'u32,
    0x82f3d055'u32, 0x66fb9767'u32, 0x15b80b4e'u32, 0x1d5b47a0'u32, 0x4cfde06f'u32, 0xc28ec4b8'u32, 0x57e8726e'u32, 0x647a78fc'u32,
    0x99865d44'u32, 0x608bd593'u32, 0x6c200e03'u32, 0x39dc5ff6'u32, 0x5d0b00a3'u32, 0xae63aff2'u32, 0x7e8bd632'u32, 0x70108c0c'u32,
    0xbbd35049'u32, 0x2998df04'u32, 0x980cf42a'u32, 0x9b6df491'u32, 0x9e7edd53'u32, 0x06918548'u32, 0x58cb7e07'u32, 0x3b74ef2e'u32,
    0x522fffb1'u32, 0xd24708cc'u32, 0x1c7e27cd'u32, 0xa4eb215b'u32, 0x3cf1d2e2'u32, 0x19b47a38'u32, 0x424f7618'u32, 0x35856039'u32,
    0x9d17dee7'u32, 0x27eb35e6'u32, 0xc9aff67b'u32, 0x36baf5b8'u32, 0x09c467cd'u32, 0xc18910b1'u32, 0xe11dbf7b'u32, 0x06cd1af8'u32,
    0x7170c608'u32, 0x2d5e3354'u32, 0xd4de495a'u32, 0x64c6d006'u32, 0xbcc0c62c'u32, 0x3dd00db3'u32, 0x708f8f34'u32, 0x77d51b42'u32,
    0x264f620f'u32, 0x24b8d2bf'u32, 0x15c1b79e'u32, 0x46a52564'u32, 0xf8d7e54e'u32, 0x3e378160'u32, 0x7895cda5'u32, 0x859c15a5'u32,
    0xe6459788'u32, 0xc37bc75f'u32, 0xdb07ba0c'u32, 0x0676a3ab'u32, 0x7f229b1e'u32, 0x31842e7b'u32, 0x24259fd7'u32, 0xf8bef472'u32,
    0x835ffcb8'u32, 0x6df4c1f2'u32, 0x96f5b195'u32, 0xfd0af0fc'u32, 0xb0fe134c'u32, 0xe2506d3d'u32, 0x4f9b12ea'u32, 0xf215f225'u32,
    0xa223736f'u32, 0x9fb4c428'u32, 0x25d04979'u32, 0x34c713f8'u32, 0xc4618187'u32, 0xea7a6e98'u32, 0x7cd16efc'u32, 0x1436876c'u32,
    0xf1544107'u32, 0xbedeee14'u32, 0x56e9af27'u32, 0xa04aa441'u32, 0x3cf7c899'u32, 0x92ecbae6'u32, 0xdd67016d'u32, 0x151682eb'u32,
    0xa842eedf'u32, 0xfdba60b4'u32, 0xf1907b75'u32, 0x20e3030f'u32, 0x24d8c29e'u32, 0xe139673b'u32, 0xefa63fb8'u32, 0x71873054'u32,
    0xb6f2cf3b'u32, 0x9f326442'u32, 0xcb15a4cc'u32, 0xb01a4504'u32, 0xf1e47d8d'u32, 0x844a1be5'u32, 0xbae7dfdc'u32, 0x42cbda70'u32,
    0xcd7dae0a'u32, 0x57e85b7a'u32, 0xd53f5af6'u32, 0x20cf4d8c'u32, 0xcea4d428'u32, 0x79d130a4'u32, 0x3486ebfb'u32, 0x33d3cddc'u32,
    0x77853b53'u32, 0x37effcb5'u32, 0xc5068778'u32, 0xe580b3e6'u32, 0x4e68b8f4'u32, 0xc5c8b37e'u32, 0x0d809ea2'u32, 0x398feb7c'u32,
    0x132a4f94'u32, 0x43b7950e'u32, 0x2fee7d1c'u32, 0x223613bd'u32, 0xdd06caa2'u32, 0x37df932b'u32, 0xc4248289'u32, 0xacf3ebc3'u32,
    0x5715f6b7'u32, 0xef3478dd'u32, 0xf267616f'u32, 0xc148cbe4'u32, 0x9052815e'u32, 0x5e410fab'u32, 0xb48a2465'u32, 0x2eda7fa4'u32,
    0xe87b40e4'u32, 0xe98ea084'u32, 0x5889e9e1'u32, 0xefd390fc'u32, 0xdd07d35b'u32, 0xdb485694'u32, 0x38d7e5b2'u32, 0x57720101'u32,
    0x730edebc'u32, 0x5b643113'u32, 0x94917e4f'u32, 0x503c2fba'u32, 0x646f1282'u32, 0x7523d24a'u32, 0xe0779695'u32, 0xf9c17a8f'u32,
    0x7a5b2121'u32, 0xd187b896'u32, 0x29263a4d'u32, 0xba510cdf'u32, 0x81f47c9f'u32, 0xad1163ed'u32, 0xea7b5965'u32, 0x1a00726e'u32,
    0x11403092'u32, 0x00da6d77'u32, 0x4a0cdd61'u32, 0xad1f4603'u32, 0x605bdfb0'u32, 0x9eedc364'u32, 0x22ebe6a8'u32, 0xcee7d28a'u32,
    0xa0e736a0'u32, 0x5564a6b9'u32, 0x10853209'u32, 0xc7eb8f37'u32, 0x2de705ca'u32, 0x8951570f'u32, 0xdf09822b'u32, 0xbd691a6c'u32,
    0xaa12e4f2'u32, 0x87451c0f'u32, 0xe0f6a27a'u32, 0x3ada4819'u32, 0x4cf1764f'u32, 0x0d771c2b'u32, 0x67cdb156'u32, 0x350d8384'u32,
    0x5938fa0f'u32, 0x42399ef3'u32, 0x36997b07'u32, 0x0e84093d'u32, 0x4aa93e61'u32, 0x8360d87b'u32, 0x1fa98b0c'u32, 0x1149382c'u32,
    0xe97625a5'u32, 0x0614d1b7'u32, 0x0e25244b'u32, 0x0c768347'u32, 0x589e8d82'u32, 0x0d2059d1'u32, 0xa466bb1e'u32, 0xf8da0a82'u32,
    0x04f19130'u32, 0xba6e4ec0'u32, 0x99265164'u32, 0x1ee7230d'u32, 0x50b2ad80'u32, 0xeaee6801'u32, 0x8db2a283'u32, 0xea8bf59e'u32
  ]

  # CAST-128 information constants
  CAST128_BLOCK_SIZE*: int = 8
  CAST128_KEY_SIZE*: int = 16

type
  # CAST-128 context
  CAST128Ctx* = object
    maskingKey*: array[16, uint32]
    rotateKey*: array[16, uint8]

# quart template
template quart(z: var array[16, uint8], z_off: int, x: array[16, uint8], x_off: int, s1, s2, s3, s4, s5: uint32): void {.autoSizeOpt.} =
  var temp: uint32 = (uint32(x[x_off + 0]) shl 24) or (uint32(x[x_off + 1]) shl 16) or (uint32(x[x_off + 2]) shl 8) or uint32(x[x_off + 3])
  temp = temp xor s1 xor s2 xor s3 xor s4 xor s5
  z[z_off + 0] = uint8((temp shr 24) and 0xFF)
  z[z_off + 1] = uint8((temp shr 16) and 0xFF)
  z[z_off + 2] = uint8((temp shr 8) and 0xFF)
  z[z_off + 3] = uint8(temp and 0xFF)

# cast init core
template cast128InitC*(ctx: var CAST128Ctx, key: slicearray[16, uint8]): void {.autoSizeOpt.} =
  var x: array[16, uint8] = key.toArray()
  var z: array[16, uint8]

  # Masking keys
  quart(z, 0, x, 0, SBox5[x[13]], SBox6[x[15]], SBox7[x[12]], SBox8[x[14]], SBox7[x[8]])
  quart(z, 4, x, 8, SBox5[z[0]], SBox6[z[2]], SBox7[z[1]], SBox8[z[3]], SBox8[x[10]])
  quart(z, 8, x, 12, SBox5[z[7]], SBox6[z[6]], SBox7[z[5]], SBox8[z[4]], SBox5[x[9]])
  quart(z, 12, x, 4, SBox5[z[10]], SBox6[z[9]], SBox7[z[11]], SBox8[z[8]], SBox6[x[11]])

  ctx.maskingKey[0] = SBox5[z[8]] xor SBox6[z[9]] xor SBox7[z[7]] xor SBox8[z[6]] xor SBox5[z[2]]
  ctx.maskingKey[1] = SBox5[z[10]] xor SBox6[z[11]] xor SBox7[z[5]] xor SBox8[z[4]] xor SBox6[z[6]]
  ctx.maskingKey[2] = SBox5[z[12]] xor SBox6[z[13]] xor SBox7[z[3]] xor SBox8[z[2]] xor SBox7[z[9]]
  ctx.maskingKey[3] = SBox5[z[14]] xor SBox6[z[15]] xor SBox7[z[1]] xor SBox8[z[0]] xor SBox8[z[12]]

  quart(x, 0, z, 8, SBox5[z[5]], SBox6[z[7]], SBox7[z[4]], SBox8[z[6]], SBox7[z[0]])
  quart(x, 4, z, 0, SBox5[x[0]], SBox6[x[2]], SBox7[x[1]], SBox8[x[3]], SBox8[z[2]])
  quart(x, 8, z, 4, SBox5[x[7]], SBox6[x[6]], SBox7[x[5]], SBox8[x[4]], SBox5[z[1]])
  quart(x, 12, z, 12, SBox5[x[10]], SBox6[x[9]], SBox7[x[11]], SBox8[x[8]], SBox6[z[3]])

  ctx.maskingKey[4] = SBox5[x[3]] xor SBox6[x[2]] xor SBox7[x[12]] xor SBox8[x[13]] xor SBox5[x[8]]
  ctx.maskingKey[5] = SBox5[x[1]] xor SBox6[x[0]] xor SBox7[x[14]] xor SBox8[x[15]] xor SBox6[x[13]]
  ctx.maskingKey[6] = SBox5[x[7]] xor SBox6[x[6]] xor SBox7[x[8]] xor SBox8[x[9]] xor SBox7[x[3]]
  ctx.maskingKey[7] = SBox5[x[5]] xor SBox6[x[4]] xor SBox7[x[10]] xor SBox8[x[11]] xor SBox8[x[7]]

  quart(z, 0, x, 0, SBox5[x[13]], SBox6[x[15]], SBox7[x[12]], SBox8[x[14]], SBox7[x[8]])
  quart(z, 4, x, 8, SBox5[z[0]], SBox6[z[2]], SBox7[z[1]], SBox8[z[3]], SBox8[x[10]])
  quart(z, 8, x, 12, SBox5[z[7]], SBox6[z[6]], SBox7[z[5]], SBox8[z[4]], SBox5[x[9]])
  quart(z, 12, x, 4, SBox5[z[10]], SBox6[z[9]], SBox7[z[11]], SBox8[z[8]], SBox6[x[11]])

  ctx.maskingKey[8] = SBox5[z[3]] xor SBox6[z[2]] xor SBox7[z[12]] xor SBox8[z[13]] xor SBox5[z[9]]
  ctx.maskingKey[9] = SBox5[z[1]] xor SBox6[z[0]] xor SBox7[z[14]] xor SBox8[z[15]] xor SBox6[z[12]]
  ctx.maskingKey[10] = SBox5[z[7]] xor SBox6[z[6]] xor SBox7[z[8]] xor SBox8[z[9]] xor SBox7[z[2]]
  ctx.maskingKey[11] = SBox5[z[5]] xor SBox6[z[4]] xor SBox7[z[10]] xor SBox8[z[11]] xor SBox8[z[6]]

  quart(x, 0, z, 8, SBox5[z[5]], SBox6[z[7]], SBox7[z[4]], SBox8[z[6]], SBox7[z[0]])
  quart(x, 4, z, 0, SBox5[x[0]], SBox6[x[2]], SBox7[x[1]], SBox8[x[3]], SBox8[z[2]])
  quart(x, 8, z, 4, SBox5[x[7]], SBox6[x[6]], SBox7[x[5]], SBox8[x[4]], SBox5[z[1]])
  quart(x, 12, z, 12, SBox5[x[10]], SBox6[x[9]], SBox7[x[11]], SBox8[x[8]], SBox6[z[3]])

  ctx.maskingKey[12] = SBox5[x[8]] xor SBox6[x[9]] xor SBox7[x[7]] xor SBox8[x[6]] xor SBox5[x[3]]
  ctx.maskingKey[13] = SBox5[x[10]] xor SBox6[x[11]] xor SBox7[x[5]] xor SBox8[x[4]] xor SBox6[x[7]]
  ctx.maskingKey[14] = SBox5[x[12]] xor SBox6[x[13]] xor SBox7[x[3]] xor SBox8[x[2]] xor SBox7[x[8]]
  ctx.maskingKey[15] = SBox5[x[14]] xor SBox6[x[15]] xor SBox7[x[1]] xor SBox8[x[0]] xor SBox8[x[13]]

  # Rotating keys
  quart(z, 0, x, 0, SBox5[x[13]], SBox6[x[15]], SBox7[x[12]], SBox8[x[14]], SBox7[x[8]])
  quart(z, 4, x, 8, SBox5[z[0]], SBox6[z[2]], SBox7[z[1]], SBox8[z[3]], SBox8[x[10]])
  quart(z, 8, x, 12, SBox5[z[7]], SBox6[z[6]], SBox7[z[5]], SBox8[z[4]], SBox5[x[9]])
  quart(z, 12, x, 4, SBox5[z[10]], SBox6[z[9]], SBox7[z[11]], SBox8[z[8]], SBox6[x[11]])

  ctx.rotateKey[0] = uint8((SBox5[z[8]] xor SBox6[z[9]] xor SBox7[z[7]] xor SBox8[z[6]] xor SBox5[z[2]]) and 0x1F)
  ctx.rotateKey[1] = uint8((SBox5[z[10]] xor SBox6[z[11]] xor SBox7[z[5]] xor SBox8[z[4]] xor SBox6[z[6]]) and 0x1F)
  ctx.rotateKey[2] = uint8((SBox5[z[12]] xor SBox6[z[13]] xor SBox7[z[3]] xor SBox8[z[2]] xor SBox7[z[9]]) and 0x1F)
  ctx.rotateKey[3] = uint8((SBox5[z[14]] xor SBox6[z[15]] xor SBox7[z[1]] xor SBox8[z[0]] xor SBox8[z[12]]) and 0x1F)

  quart(x, 0, z, 8, SBox5[z[5]], SBox6[z[7]], SBox7[z[4]], SBox8[z[6]], SBox7[z[0]])
  quart(x, 4, z, 0, SBox5[x[0]], SBox6[x[2]], SBox7[x[1]], SBox8[x[3]], SBox8[z[2]])
  quart(x, 8, z, 4, SBox5[x[7]], SBox6[x[6]], SBox7[x[5]], SBox8[x[4]], SBox5[z[1]])
  quart(x, 12, z, 12, SBox5[x[10]], SBox6[x[9]], SBox7[x[11]], SBox8[x[8]], SBox6[z[3]])

  ctx.rotateKey[4] = uint8((SBox5[x[3]] xor SBox6[x[2]] xor SBox7[x[12]] xor SBox8[x[13]] xor SBox5[x[8]]) and 0x1F)
  ctx.rotateKey[5] = uint8((SBox5[x[1]] xor SBox6[x[0]] xor SBox7[x[14]] xor SBox8[x[15]] xor SBox6[x[13]]) and 0x1F)
  ctx.rotateKey[6] = uint8((SBox5[x[7]] xor SBox6[x[6]] xor SBox7[x[8]] xor SBox8[x[9]] xor SBox7[x[3]]) and 0x1F)
  ctx.rotateKey[7] = uint8((SBox5[x[5]] xor SBox6[x[4]] xor SBox7[x[10]] xor SBox8[x[11]] xor SBox8[x[7]]) and 0x1F)

  quart(z, 0, x, 0, SBox5[x[13]], SBox6[x[15]], SBox7[x[12]], SBox8[x[14]], SBox7[x[8]])
  quart(z, 4, x, 8, SBox5[z[0]], SBox6[z[2]], SBox7[z[1]], SBox8[z[3]], SBox8[x[10]])
  quart(z, 8, x, 12, SBox5[z[7]], SBox6[z[6]], SBox7[z[5]], SBox8[z[4]], SBox5[x[9]])
  quart(z, 12, x, 4, SBox5[z[10]], SBox6[z[9]], SBox7[z[11]], SBox8[z[8]], SBox6[x[11]])

  ctx.rotateKey[8] = uint8((SBox5[z[3]] xor SBox6[z[2]] xor SBox7[z[12]] xor SBox8[z[13]] xor SBox5[z[9]]) and 0x1F)
  ctx.rotateKey[9] = uint8((SBox5[z[1]] xor SBox6[z[0]] xor SBox7[z[14]] xor SBox8[z[15]] xor SBox6[z[12]]) and 0x1F)
  ctx.rotateKey[10] = uint8((SBox5[z[7]] xor SBox6[z[6]] xor SBox7[z[8]] xor SBox8[z[9]] xor SBox7[z[2]]) and 0x1F)
  ctx.rotateKey[11] = uint8((SBox5[z[5]] xor SBox6[z[4]] xor SBox7[z[10]] xor SBox8[z[11]] xor SBox8[z[6]]) and 0x1F)

  quart(x, 0, z, 8, SBox5[z[5]], SBox6[z[7]], SBox7[z[4]], SBox8[z[6]], SBox7[z[0]])
  quart(x, 4, z, 0, SBox5[x[0]], SBox6[x[2]], SBox7[x[1]], SBox8[x[3]], SBox8[z[2]])
  quart(x, 8, z, 4, SBox5[x[7]], SBox6[x[6]], SBox7[x[5]], SBox8[x[4]], SBox5[z[1]])
  quart(x, 12, z, 12, SBox5[x[10]], SBox6[x[9]], SBox7[x[11]], SBox8[x[8]], SBox6[z[3]])

  ctx.rotateKey[12] = uint8((SBox5[x[8]] xor SBox6[x[9]] xor SBox7[x[7]] xor SBox8[x[6]] xor SBox5[x[3]]) and 0x1F)
  ctx.rotateKey[13] = uint8((SBox5[x[10]] xor SBox6[x[11]] xor SBox7[x[5]] xor SBox8[x[4]] xor SBox6[x[7]]) and 0x1F)
  ctx.rotateKey[14] = uint8((SBox5[x[12]] xor SBox6[x[13]] xor SBox7[x[3]] xor SBox8[x[2]] xor SBox7[x[8]]) and 0x1F)
  ctx.rotateKey[15] = uint8((SBox5[x[14]] xor SBox6[x[15]] xor SBox7[x[1]] xor SBox8[x[0]] xor SBox8[x[13]]) and 0x1F)

# F1 template
template F1(data: uint32, maskingKey: uint32, rotateKey: uint8): uint32 {.autoSizeOpt.} = 
  let iValue: uint32 = rotateLeftBits(data + maskingKey, rotateKey)
  
  let ia: uint8 = uint8((iValue shr 24) and 0xFF)
  let ib: uint8 = uint8((iValue shr 16) and 0xFF)
  let ic: uint8 = uint8((iValue shr 8) and 0xFF)
  let id: uint8 = uint8(iValue and 0xFF)

  ((SBox1[ia] xor SBox2[ib]) - SBox3[ic] + SBox4[id]) 

# F2 template
template F2(data: uint32, maskingKey: uint32, rotateKey: uint8): uint32 {.autoSizeOpt.} =
  let iValue: uint32 = rotateLeftBits(data xor maskingKey, rotateKey)

  let ia: uint8 = uint8((iValue shr 24) and 0xFF)
  let ib: uint8 = uint8((iValue shr 16) and 0xFF)
  let ic: uint8 = uint8((iValue shr 8) and 0xFF)
  let id: uint8 = uint8(iValue and 0xFF)

  (SBox1[ia] - SBox2[ib] + SBox3[ic]) xor SBox4[id]

# F3 template
template F3(data: uint32, maskingKey: uint32, rotateKey: uint8): uint32 {.autoSizeOpt.} =
  let iValue: uint32 = rotateLeftBits(maskingKey - data, rotateKey)

  let ia: uint8 = uint8((iValue shr 24) and 0xFF)
  let ib: uint8 = uint8((iValue shr 16) and 0xFF)
  let ic: uint8 = uint8((iValue shr 8) and 0xFF)
  let id: uint8 = uint8(iValue and 0xFF)

  ((SBox1[ia] + SBox2[ib]) xor SBox3[ic]) - SBox4[id]

# encrypt round template
template EncyptRound(f: untyped, left, right: var uint32, maskingKey: uint32, rotateKey: uint8): void =
  let oldLeft: uint32 = left
  left = right
  right = oldLeft xor f(right, maskingKey, rotateKey)

# decrypt round template
template DecryptRound(f: untyped, left, right: var uint32, maskingKey: uint32, rotateKey: uint8): void =
  let oldLeft: uint32 = left
  left = right xor f(left, maskingKey, rotateKey)
  right = oldLeft

# cast 128 encrypt core
template cast128EncryptC*(ctx: CAST128Ctx, input, output: slicearray[8, uint8]): void {.autoSizeOpt.} =
  # set left and right variables
  var left, right: uint32
  fromBytesBE(input.toSliceArray(0, 3), left)
  fromBytesBE(input.toSliceArray(4, 7), right)

  # call encrypt rounds
  EncyptRound(F1, left, right, ctx.maskingKey[0], ctx.rotateKey[0])
  EncyptRound(F2, left, right, ctx.maskingKey[1], ctx.rotateKey[1])
  EncyptRound(F3, left, right, ctx.maskingKey[2], ctx.rotateKey[2])
  EncyptRound(F1, left, right, ctx.maskingKey[3], ctx.rotateKey[3])
  EncyptRound(F2, left, right, ctx.maskingKey[4], ctx.rotateKey[4])
  EncyptRound(F3, left, right, ctx.maskingKey[5], ctx.rotateKey[5])
  EncyptRound(F1, left, right, ctx.maskingKey[6], ctx.rotateKey[6])
  EncyptRound(F2, left, right, ctx.maskingKey[7], ctx.rotateKey[7])
  EncyptRound(F3, left, right, ctx.maskingKey[8], ctx.rotateKey[8])
  EncyptRound(F1, left, right, ctx.maskingKey[9], ctx.rotateKey[9])
  EncyptRound(F2, left, right, ctx.maskingKey[10], ctx.rotateKey[10])
  EncyptRound(F3, left, right, ctx.maskingKey[11], ctx.rotateKey[11])
  EncyptRound(F1, left, right, ctx.maskingKey[12], ctx.rotateKey[12])
  EncyptRound(F2, left, right, ctx.maskingKey[13], ctx.rotateKey[13])
  EncyptRound(F3, left, right, ctx.maskingKey[14], ctx.rotateKey[14])
  EncyptRound(F1, left, right, ctx.maskingKey[15], ctx.rotateKey[15])

  # encode right to state
  toBytesBE(right, output.toSliceArray(0, 3))
  toBytesBE(left, output.toSliceArray(4, 7))

# cast 128 decrypt core
template cast128DecryptC*(ctx: CAST128Ctx, input, output: slicearray[8, uint8]): void {.autoSizeOpt.} =
  # set left and right variables
  var left, right: uint32
  fromBytesBE(input.toSliceArray(0, 3), right)
  fromBytesBE(input.toSliceArray(4, 7), left)

  # call decrypt rounds
  DecryptRound(F1, left, right, ctx.maskingKey[15], ctx.rotateKey[15])
  DecryptRound(F3, left, right, ctx.maskingKey[14], ctx.rotateKey[14])
  DecryptRound(F2, left, right, ctx.maskingKey[13], ctx.rotateKey[13])
  DecryptRound(F1, left, right, ctx.maskingKey[12], ctx.rotateKey[12])
  DecryptRound(F3, left, right, ctx.maskingKey[11], ctx.rotateKey[11])
  DecryptRound(F2, left, right, ctx.maskingKey[10], ctx.rotateKey[10])
  DecryptRound(F1, left, right, ctx.maskingKey[9], ctx.rotateKey[9])
  DecryptRound(F3, left, right, ctx.maskingKey[8], ctx.rotateKey[8])
  DecryptRound(F2, left, right, ctx.maskingKey[7], ctx.rotateKey[7])
  DecryptRound(F1, left, right, ctx.maskingKey[6], ctx.rotateKey[6])
  DecryptRound(F3, left, right, ctx.maskingKey[5], ctx.rotateKey[5])
  DecryptRound(F2, left, right, ctx.maskingKey[4], ctx.rotateKey[4])
  DecryptRound(F1, left, right, ctx.maskingKey[3], ctx.rotateKey[3])
  DecryptRound(F3, left, right, ctx.maskingKey[2], ctx.rotateKey[2])
  DecryptRound(F2, left, right, ctx.maskingKey[1], ctx.rotateKey[1])
  DecryptRound(F1, left, right, ctx.maskingKey[0], ctx.rotateKey[0])

  # encode left and right to state
  toBytesBE(left, output.toSliceArray(0, 3))
  toBytesBE(right, output.toSliceArray(4, 7))

# export wrappers
when defined(templateOpt):
  template cast128Init*(ctx: var CAST128Ctx, key: array[16, uint8]): void =
    cast128InitC(ctx, key.toSliceArray(0, 15))
  template cast128Init*(ctx: var CAST128Ctx, key: openArray[uint8]): void =
    cast128InitC(ctx, key.toSliceArray(0, 15))
  template cast128Init*(ctx: var CAST128Ctx, key: slicearray[16, uint8]): void =
    cast128InitC(ctx, key)
  template cast128Init*(ctx: var CAST128Ctx, key: ptr array[16, uint8]): void =
    cast128InitC(ctx, key.toSliceArray(0, 15))

  template cast128Encrypt*(ctx: CAST128Ctx, input: array[8, uint8], output: var array[8, uint8]): void =
    cast128EncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template cast128Encrypt*(ctx: CAST128Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    cast128EncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template cast128Encrypt*(ctx: CAST128Ctx, input, output: slicearray[8, uint8]): void =
    cast128EncryptC(ctx, input, output)
  template cast128Encrypt*(ctx: CAST128Ctx, input, output: ptr array[8, uint8]): void =
    cast128EncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  template cast128Decrypt*(ctx: CAST128Ctx, input: array[8, uint8], output: var array[8, uint8]): void =
    cast128DecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template cast128Decrypt*(ctx: CAST128Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    cast128DecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template cast128Decrypt*(ctx: CAST128Ctx, input, output: slicearray[8, uint8]): void =
    cast128DecryptC(ctx, input, output)
  template cast128Decrypt*(ctx: CAST128Ctx, input, output: ptr array[8, uint8]): void =
    cast128DecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
else:
  proc cast128Init*(ctx: var CAST128Ctx, key: array[16, uint8]): void =
    cast128InitC(ctx, key.toSliceArray(0, 15))
  proc cast128Init*(ctx: var CAST128Ctx, key: openArray[uint8]): void =
    cast128InitC(ctx, key.toSliceArray(0, 15))
  proc cast128Init*(ctx: var CAST128Ctx, key: slicearray[16, uint8]): void =
    cast128InitC(ctx, key)
  proc cast128Init*(ctx: var CAST128Ctx, key: ptr array[16, uint8]): void {.exportc: "cast128Init".} =
    cast128InitC(ctx, key.toSliceArray(0, 15))

  proc cast128Encrypt*(ctx: CAST128Ctx, input: array[8, uint8], output: var array[8, uint8]): void =
    cast128EncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc cast128Encrypt*(ctx: CAST128Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    cast128EncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc cast128Encrypt*(ctx: CAST128Ctx, input, output: slicearray[8, uint8]): void =
    cast128EncryptC(ctx, input, output)
  proc cast128Encrypt*(ctx: CAST128Ctx, input, output: ptr array[8, uint8]): void {.exportc: "cast128Encrypt".} =
    cast128EncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  proc cast128Decrypt*(ctx: CAST128Ctx, input: array[8, uint8], output: var array[8, uint8]): void =
    cast128DecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc cast128Decrypt*(ctx: CAST128Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    cast128DecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc cast128Decrypt*(ctx: CAST128Ctx, input, output: slicearray[8, uint8]): void =
    cast128DecryptC(ctx, input, output)
  proc cast128Decrypt*(ctx: CAST128Ctx, input, output: ptr array[8, uint8]): void {.exportc: "cast128Decrypt".} =
    cast128DecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
