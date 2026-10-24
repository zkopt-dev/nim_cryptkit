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
  # declare SBox 1 ~ 4
  SBox1: array[256, uint32] = [
    0x30FB40D4'u32, 0x9FA0FF0B'u32, 0x6BECCD2F'u32, 0x3F258C7A'u32, 0x1E213F2F'u32, 0x9C004DD3'u32, 0x6003E540'u32, 0xCF9FC949'u32,
    0xBFD4AF27'u32, 0x88BBBDB5'u32, 0xE2034090'u32, 0x98D09675'u32, 0x6E63A0E0'u32, 0x15C361D2'u32, 0xC2E7661D'u32, 0x22D4FF8E'u32,
    0x28683B6F'u32, 0xC07FD059'u32, 0xFF2379C8'u32, 0x775F50E2'u32, 0x43C340D3'u32, 0xDF2F8656'u32, 0x887CA41A'u32, 0xA2D2BD2D'u32,
    0xA1C9E0D6'u32, 0x346C4819'u32, 0x61B76D87'u32, 0x22540F2F'u32, 0x2ABE32E1'u32, 0xAA54166B'u32, 0x22568E3A'u32, 0xA2D341D0'u32,
    0x66DB40C8'u32, 0xA784392F'u32, 0x004DFF2F'u32, 0x2DB9D2DE'u32, 0x97943FAC'u32, 0x4A97C1D8'u32, 0x527644B7'u32, 0xB5F437A7'u32,
    0xB82CBAEF'u32, 0xD751D159'u32, 0x6FF7F0ED'u32, 0x5A097A1F'u32, 0x827B68D0'u32, 0x90ECF52E'u32, 0x22B0C054'u32, 0xBC8E5935'u32,
    0x4B6D2F7F'u32, 0x50BB64A2'u32, 0xD2664910'u32, 0xBEE5812D'u32, 0xB7332290'u32, 0xE93B159F'u32, 0xB48EE411'u32, 0x4BFF345D'u32,
    0xFD45C240'u32, 0xAD31973F'u32, 0xC4F6D02E'u32, 0x55FC8165'u32, 0xD5B1CAAD'u32, 0xA1AC2DAE'u32, 0xA2D4B76D'u32, 0xC19B0C50'u32,
    0x882240F2'u32, 0x0C6E4F38'u32, 0xA4E4BFD7'u32, 0x4F5BA272'u32, 0x564C1D2F'u32, 0xC59C5319'u32, 0xB949E354'u32, 0xB04669FE'u32,
    0xB1B6AB8A'u32, 0xC71358DD'u32, 0x6385C545'u32, 0x110F935D'u32, 0x57538AD5'u32, 0x6A390493'u32, 0xE63D37E0'u32, 0x2A54F6B3'u32,
    0x3A787D5F'u32, 0x6276A0B5'u32, 0x19A6FCDF'u32, 0x7A42206A'u32, 0x29F9D4D5'u32, 0xF61B1891'u32, 0xBB72275E'u32, 0xAA508167'u32,
    0x38901091'u32, 0xC6B505EB'u32, 0x84C7CB8C'u32, 0x2AD75A0F'u32, 0x874A1427'u32, 0xA2D1936B'u32, 0x2AD286AF'u32, 0xAA56D291'u32,
    0xD7894360'u32, 0x425C750D'u32, 0x93B39E26'u32, 0x187184C9'u32, 0x6C00B32D'u32, 0x73E2BB14'u32, 0xA0BEBC3C'u32, 0x54623779'u32,
    0x64459EAB'u32, 0x3F328B82'u32, 0x7718CF82'u32, 0x59A2CEA6'u32, 0x04EE002E'u32, 0x89FE78E6'u32, 0x3FAB0950'u32, 0x325FF6C2'u32,
    0x81383F05'u32, 0x6963C5C8'u32, 0x76CB5AD6'u32, 0xD49974C9'u32, 0xCA180DCF'u32, 0x380782D5'u32, 0xC7FA5CF6'u32, 0x8AC31511'u32,
    0x35E79E13'u32, 0x47DA91D0'u32, 0xF40F9086'u32, 0xA7E2419E'u32, 0x31366241'u32, 0x051EF495'u32, 0xAA573B04'u32, 0x4A805D8D'u32,
    0x548300D0'u32, 0x00322A3C'u32, 0xBF64CDDF'u32, 0xBA57A68E'u32, 0x75C6372B'u32, 0x50AFD341'u32, 0xA7C13275'u32, 0x915A0BF5'u32,
    0x6B54BFAB'u32, 0x2B0B1426'u32, 0xAB4CC9D7'u32, 0x449CCD82'u32, 0xF7FBF265'u32, 0xAB85C5F3'u32, 0x1B55DB94'u32, 0xAAD4E324'u32,
    0xCFA4BD3F'u32, 0x2DEAA3E2'u32, 0x9E204D02'u32, 0xC8BD25AC'u32, 0xEADF55B3'u32, 0xD5BD9E98'u32, 0xE31231B2'u32, 0x2AD5AD6C'u32,
    0x954329DE'u32, 0xADBE4528'u32, 0xD8710F69'u32, 0xAA51C90F'u32, 0xAA786BF6'u32, 0x22513F1E'u32, 0xAA51A79B'u32, 0x2AD344CC'u32,
    0x7B5A41F0'u32, 0xD37CFBAD'u32, 0x1B069505'u32, 0x41ECE491'u32, 0xB4C332E6'u32, 0x032268D4'u32, 0xC9600ACC'u32, 0xCE387E6D'u32,
    0xBF6BB16C'u32, 0x6A70FB78'u32, 0x0D03D9C9'u32, 0xD4DF39DE'u32, 0xE01063DA'u32, 0x4736F464'u32, 0x5AD328D8'u32, 0xB347CC96'u32,
    0x75BB0FC3'u32, 0x98511BFB'u32, 0x4FFBCC35'u32, 0xB58BCF6A'u32, 0xE11F0ABC'u32, 0xBFC5FE4A'u32, 0xA70AEC10'u32, 0xAC39570A'u32,
    0x3F04442F'u32, 0x6188B153'u32, 0xE0397A2E'u32, 0x5727CB79'u32, 0x9CEB418F'u32, 0x1CACD68D'u32, 0x2AD37C96'u32, 0x0175CB9D'u32,
    0xC69DFF09'u32, 0xC75B65F0'u32, 0xD9DB40D8'u32, 0xEC0E7779'u32, 0x4744EAD4'u32, 0xB11C3274'u32, 0xDD24CB9E'u32, 0x7E1C54BD'u32,
    0xF01144F9'u32, 0xD2240EB1'u32, 0x9675B3FD'u32, 0xA3AC3755'u32, 0xD47C27AF'u32, 0x51C85F4D'u32, 0x56907596'u32, 0xA5BB15E6'u32,
    0x580304F0'u32, 0xCA042CF1'u32, 0x011A37EA'u32, 0x8DBFAADB'u32, 0x35BA3E4A'u32, 0x3526FFA0'u32, 0xC37B4D09'u32, 0xBC306ED9'u32,
    0x98A52666'u32, 0x5648F725'u32, 0xFF5E569D'u32, 0x0CED63D0'u32, 0x7C63B2CF'u32, 0x700B45E1'u32, 0xD5EA50F1'u32, 0x85A92872'u32,
    0xAF1FBDA7'u32, 0xD4234870'u32, 0xA7870BF3'u32, 0x2D3B4D79'u32, 0x42E04198'u32, 0x0CD0EDE7'u32, 0x26470DB8'u32, 0xF881814C'u32,
    0x474D6AD7'u32, 0x7C0C5E5C'u32, 0xD1231959'u32, 0x381B7298'u32, 0xF5D2F4DB'u32, 0xAB838653'u32, 0x6E2F1E23'u32, 0x83719C9E'u32,
    0xBD91E046'u32, 0x9A56456E'u32, 0xDC39200C'u32, 0x20C8C571'u32, 0x962BDA1C'u32, 0xE1E696FF'u32, 0xB141AB08'u32, 0x7CCA89B9'u32,
    0x1A69E783'u32, 0x02CC4843'u32, 0xA2F7C579'u32, 0x429EF47D'u32, 0x427B169C'u32, 0x5AC9F049'u32, 0xDD8F0F00'u32, 0x5C8165BF'u32
  ]
  SBox2*: array[256, uint32] = [
    0x1F201094'u32, 0xEF0BA75B'u32, 0x69E3CF7E'u32, 0x393F4380'u32, 0xFE61CF7A'u32, 0xEEC5207A'u32, 0x55889C94'u32, 0x72FC0651'u32,
    0xADA7EF79'u32, 0x4E1D7235'u32, 0xD55A63CE'u32, 0xDE0436BA'u32, 0x99C430EF'u32, 0x5F0C0794'u32, 0x18DCDB7D'u32, 0xA1D6EFF3'u32,
    0xA0B52F7B'u32, 0x59E83605'u32, 0xEE15B094'u32, 0xE9FFD909'u32, 0xDC440086'u32, 0xEF944459'u32, 0xBA83CCB3'u32, 0xE0C3CDFB'u32,
    0xD1DA4181'u32, 0x3B092AB1'u32, 0xF997F1C1'u32, 0xA5E6CF7B'u32, 0x01420DDB'u32, 0xE4E7EF5B'u32, 0x25A1FF41'u32, 0xE180F806'u32,
    0x1FC41080'u32, 0x179BEE7A'u32, 0xD37AC6A9'u32, 0xFE5830A4'u32, 0x98DE8B7F'u32, 0x77E83F4E'u32, 0x79929269'u32, 0x24FA9F7B'u32,
    0xE113C85B'u32, 0xACC40083'u32, 0xD7503525'u32, 0xF7EA615F'u32, 0x62143154'u32, 0x0D554B63'u32, 0x5D681121'u32, 0xC866C359'u32,
    0x3D63CF73'u32, 0xCEE234C0'u32, 0xD4D87E87'u32, 0x5C672B21'u32, 0x071F6181'u32, 0x39F7627F'u32, 0x361E3084'u32, 0xE4EB573B'u32,
    0x602F64A4'u32, 0xD63ACD9C'u32, 0x1BBC4635'u32, 0x9E81032D'u32, 0x2701F50C'u32, 0x99847AB4'u32, 0xA0E3DF79'u32, 0xBA6CF38C'u32,
    0x10843094'u32, 0x2537A95E'u32, 0xF46F6FFE'u32, 0xA1FF3B1F'u32, 0x208CFB6A'u32, 0x8F458C74'u32, 0xD9E0A227'u32, 0x4EC73A34'u32,
    0xFC884F69'u32, 0x3E4DE8DF'u32, 0xEF0E0088'u32, 0x3559648D'u32, 0x8A45388C'u32, 0x1D804366'u32, 0x721D9BFD'u32, 0xA58684BB'u32,
    0xE8256333'u32, 0x844E8212'u32, 0x128D8098'u32, 0xFED33FB4'u32, 0xCE280AE1'u32, 0x27E19BA5'u32, 0xD5A6C252'u32, 0xE49754BD'u32,
    0xC5D655DD'u32, 0xEB667064'u32, 0x77840B4D'u32, 0xA1B6A801'u32, 0x84DB26A9'u32, 0xE0B56714'u32, 0x21F043B7'u32, 0xE5D05860'u32,
    0x54F03084'u32, 0x066FF472'u32, 0xA31AA153'u32, 0xDADC4755'u32, 0xB5625DBF'u32, 0x68561BE6'u32, 0x83CA6B94'u32, 0x2D6ED23B'u32,
    0xECCF01DB'u32, 0xA6D3D0BA'u32, 0xB6803D5C'u32, 0xAF77A709'u32, 0x33B4A34C'u32, 0x397BC8D6'u32, 0x5EE22B95'u32, 0x5F0E5304'u32,
    0x81ED6F61'u32, 0x20E74364'u32, 0xB45E1378'u32, 0xDE18639B'u32, 0x881CA122'u32, 0xB96726D1'u32, 0x8049A7E8'u32, 0x22B7DA7B'u32,
    0x5E552D25'u32, 0x5272D237'u32, 0x79D2951C'u32, 0xC60D894C'u32, 0x488CB402'u32, 0x1BA4FE5B'u32, 0xA4B09F6B'u32, 0x1CA815CF'u32,
    0xA20C3005'u32, 0x8871DF63'u32, 0xB9DE2FCB'u32, 0x0CC6C9E9'u32, 0x0BEEFF53'u32, 0xE3214517'u32, 0xB4542835'u32, 0x9F63293C'u32,
    0xEE41E729'u32, 0x6E1D2D7C'u32, 0x50045286'u32, 0x1E6685F3'u32, 0xF33401C6'u32, 0x30A22C95'u32, 0x31A70850'u32, 0x60930F13'u32,
    0x73F98417'u32, 0xA1269859'u32, 0xEC645C44'u32, 0x52C877A9'u32, 0xCDFF33A6'u32, 0xA02B1741'u32, 0x7CBAD9A2'u32, 0x2180036F'u32,
    0x50D99C08'u32, 0xCB3F4861'u32, 0xC26BD765'u32, 0x64A3F6AB'u32, 0x80342676'u32, 0x25A75E7B'u32, 0xE4E6D1FC'u32, 0x20C710E6'u32,
    0xCDF0B680'u32, 0x17844D3B'u32, 0x31EEF84D'u32, 0x7E0824E4'u32, 0x2CCB49EB'u32, 0x846A3BAE'u32, 0x8FF77888'u32, 0xEE5D60F6'u32,
    0x7AF75673'u32, 0x2FDD5CDB'u32, 0xA11631C1'u32, 0x30F66F43'u32, 0xB3FAEC54'u32, 0x157FD7FA'u32, 0xEF8579CC'u32, 0xD152DE58'u32,
    0xDB2FFD5E'u32, 0x8F32CE19'u32, 0x306AF97A'u32, 0x02F03EF8'u32, 0x99319AD5'u32, 0xC242FA0F'u32, 0xA7E3EBB0'u32, 0xC68E4906'u32,
    0xB8DA230C'u32, 0x80823028'u32, 0xDCDEF3C8'u32, 0xD35FB171'u32, 0x088A1BC8'u32, 0xBEC0C560'u32, 0x61A3C9E8'u32, 0xBCA8F54D'u32,
    0xC72FEFFA'u32, 0x22822E99'u32, 0x82C570B4'u32, 0xD8D94E89'u32, 0x8B1C34BC'u32, 0x301E16E6'u32, 0x273BE979'u32, 0xB0FFEAA6'u32,
    0x61D9B8C6'u32, 0x00B24869'u32, 0xB7FFCE3F'u32, 0x08DC283B'u32, 0x43DAF65A'u32, 0xF7E19798'u32, 0x7619B72F'u32, 0x8F1C9BA4'u32,
    0xDC8637A0'u32, 0x16A7D3B1'u32, 0x9FC393B7'u32, 0xA7136EEB'u32, 0xC6BCC63E'u32, 0x1A513742'u32, 0xEF6828BC'u32, 0x520365D6'u32,
    0x2D6A77AB'u32, 0x3527ED4B'u32, 0x821FD216'u32, 0x095C6E2E'u32, 0xDB92F2FB'u32, 0x5EEA29CB'u32, 0x145892F5'u32, 0x91584F7F'u32,
    0x5483697B'u32, 0x2667A8CC'u32, 0x85196048'u32, 0x8C4BACEA'u32, 0x833860D4'u32, 0x0D23E0F9'u32, 0x6C387E8A'u32, 0x0AE6D249'u32,
    0xB284600C'u32, 0xD835731D'u32, 0xDCB1C647'u32, 0xAC4C56EA'u32, 0x3EBD81B3'u32, 0x230EABB0'u32, 0x6438BC87'u32, 0xF0B5B1FA'u32,
    0x8F5EA2B3'u32, 0xFC184642'u32, 0x0A036B7A'u32, 0x4FB089BD'u32, 0x649DA589'u32, 0xA345415E'u32, 0x5C038323'u32, 0x3E5D3BB9'u32,
    0x43D79572'u32, 0x7E6DD07C'u32, 0x06DFDF1E'u32, 0x6C6CC4EF'u32, 0x7160A539'u32, 0x73BFBE70'u32, 0x83877605'u32, 0x4523ECF1'u32
  ]
  SBox3: array[256, uint32] = [
    0x8DEFC240'u32, 0x25FA5D9F'u32, 0xEB903DBF'u32, 0xE810C907'u32, 0x47607FFF'u32, 0x369FE44B'u32, 0x8C1FC644'u32, 0xAECECA90'u32,
    0xBEB1F9BF'u32, 0xEEFBCAEA'u32, 0xE8CF1950'u32, 0x51DF07AE'u32, 0x920E8806'u32, 0xF0AD0548'u32, 0xE13C8D83'u32, 0x927010D5'u32,
    0x11107D9F'u32, 0x07647DB9'u32, 0xB2E3E4D4'u32, 0x3D4F285E'u32, 0xB9AFA820'u32, 0xFADE82E0'u32, 0xA067268B'u32, 0x8272792E'u32,
    0x553FB2C0'u32, 0x489AE22B'u32, 0xD4EF9794'u32, 0x125E3FBC'u32, 0x21FFFCEE'u32, 0x825B1BFD'u32, 0x9255C5ED'u32, 0x1257A240'u32,
    0x4E1A8302'u32, 0xBAE07FFF'u32, 0x528246E7'u32, 0x8E57140E'u32, 0x3373F7BF'u32, 0x8C9F8188'u32, 0xA6FC4EE8'u32, 0xC982B5A5'u32,
    0xA8C01DB7'u32, 0x579FC264'u32, 0x67094F31'u32, 0xF2BD3F5F'u32, 0x40FFF7C1'u32, 0x1FB78DFC'u32, 0x8E6BD2C1'u32, 0x437BE59B'u32,
    0x99B03DBF'u32, 0xB5DBC64B'u32, 0x638DC0E6'u32, 0x55819D99'u32, 0xA197C81C'u32, 0x4A012D6E'u32, 0xC5884A28'u32, 0xCCC36F71'u32,
    0xB843C213'u32, 0x6C0743F1'u32, 0x8309893C'u32, 0x0FEDDD5F'u32, 0x2F7FE850'u32, 0xD7C07F7E'u32, 0x02507FBF'u32, 0x5AFB9A04'u32,
    0xA747D2D0'u32, 0x1651192E'u32, 0xAF70BF3E'u32, 0x58C31380'u32, 0x5F98302E'u32, 0x727CC3C4'u32, 0x0A0FB402'u32, 0x0F7FEF82'u32,
    0x8C96FDAD'u32, 0x5D2C2AAE'u32, 0x8EE99A49'u32, 0x50DA88B8'u32, 0x8427F4A0'u32, 0x1EAC5790'u32, 0x796FB449'u32, 0x8252DC15'u32,
    0xEFBD7D9B'u32, 0xA672597D'u32, 0xADA840D8'u32, 0x45F54504'u32, 0xFA5D7403'u32, 0xE83EC305'u32, 0x4F91751A'u32, 0x925669C2'u32,
    0x23EFE941'u32, 0xA903F12E'u32, 0x60270DF2'u32, 0x0276E4B6'u32, 0x94FD6574'u32, 0x927985B2'u32, 0x8276DBCB'u32, 0x02778176'u32,
    0xF8AF918D'u32, 0x4E48F79E'u32, 0x8F616DDF'u32, 0xE29D840E'u32, 0x842F7D83'u32, 0x340CE5C8'u32, 0x96BBB682'u32, 0x93B4B148'u32,
    0xEF303CAB'u32, 0x984FAF28'u32, 0x779FAF9B'u32, 0x92DC560D'u32, 0x224D1E20'u32, 0x8437AA88'u32, 0x7D29DC96'u32, 0x2756D3DC'u32,
    0x8B907CEE'u32, 0xB51FD240'u32, 0xE7C07CE3'u32, 0xE566B4A1'u32, 0xC3E9615E'u32, 0x3CF8209D'u32, 0x6094D1E3'u32, 0xCD9CA341'u32,
    0x5C76460E'u32, 0x00EA983B'u32, 0xD4D67881'u32, 0xFD47572C'u32, 0xF76CEDD9'u32, 0xBDA8229C'u32, 0x127DADAA'u32, 0x438A074E'u32,
    0x1F97C090'u32, 0x081BDB8A'u32, 0x93A07EBE'u32, 0xB938CA15'u32, 0x97B03CFF'u32, 0x3DC2C0F8'u32, 0x8D1AB2EC'u32, 0x64380E51'u32,
    0x68CC7BFB'u32, 0xD90F2788'u32, 0x12490181'u32, 0x5DE5FFD4'u32, 0xDD7EF86A'u32, 0x76A2E214'u32, 0xB9A40368'u32, 0x925D958F'u32,
    0x4B39FFFA'u32, 0xBA39AEE9'u32, 0xA4FFD30B'u32, 0xFAF7933B'u32, 0x6D498623'u32, 0x193CBCFA'u32, 0x27627545'u32, 0x825CF47A'u32,
    0x61BD8BA0'u32, 0xD11E42D1'u32, 0xCEAD04F4'u32, 0x127EA392'u32, 0x10428DB7'u32, 0x8272A972'u32, 0x9270C4A8'u32, 0x127DE50B'u32,
    0x285BA1C8'u32, 0x3C62F44F'u32, 0x35C0EAA5'u32, 0xE805D231'u32, 0x428929FB'u32, 0xB4FCDF82'u32, 0x4FB66A53'u32, 0x0E7DC15B'u32,
    0x1F081FAB'u32, 0x108618AE'u32, 0xFCFD086D'u32, 0xF9FF2889'u32, 0x694BCC11'u32, 0x236A5CAE'u32, 0x12DECA4D'u32, 0x2C3F8CC5'u32,
    0xD2D02DFE'u32, 0xF8EF5896'u32, 0xE4CF52DA'u32, 0x95155B67'u32, 0x494A488C'u32, 0xB9B6A80C'u32, 0x5C8F82BC'u32, 0x89D36B45'u32,
    0x3A609437'u32, 0xEC00C9A9'u32, 0x44715253'u32, 0x0A874B49'u32, 0xD773BC40'u32, 0x7C34671C'u32, 0x02717EF6'u32, 0x4FEB5536'u32,
    0xA2D02FFF'u32, 0xD2BF60C4'u32, 0xD43F03C0'u32, 0x50B4EF6D'u32, 0x07478CD1'u32, 0x006E1888'u32, 0xA2E53F55'u32, 0xB9E6D4BC'u32,
    0xA2048016'u32, 0x97573833'u32, 0xD7207D67'u32, 0xDE0F8F3D'u32, 0x72F87B33'u32, 0xABCC4F33'u32, 0x7688C55D'u32, 0x7B00A6B0'u32,
    0x947B0001'u32, 0x570075D2'u32, 0xF9BB88F8'u32, 0x8942019E'u32, 0x4264A5FF'u32, 0x856302E0'u32, 0x72DBD92B'u32, 0xEE971B69'u32,
    0x6EA22FDE'u32, 0x5F08AE2B'u32, 0xAF7A616D'u32, 0xE5C98767'u32, 0xCF1FEBD2'u32, 0x61EFC8C2'u32, 0xF1AC2571'u32, 0xCC8239C2'u32,
    0x67214CB8'u32, 0xB1E583D1'u32, 0xB7DC3E62'u32, 0x7F10BDCE'u32, 0xF90A5C38'u32, 0x0FF0443D'u32, 0x606E6DC6'u32, 0x60543A49'u32,
    0x5727C148'u32, 0x2BE98A1D'u32, 0x8AB41738'u32, 0x20E1BE24'u32, 0xAF96DA0F'u32, 0x68458425'u32, 0x99833BE5'u32, 0x600D457D'u32,
    0x282F9350'u32, 0x8334B362'u32, 0xD91D1120'u32, 0x2B6D8DA0'u32, 0x642B1E31'u32, 0x9C305A00'u32, 0x52BCE688'u32, 0x1B03588A'u32,
    0xF7BAEFD5'u32, 0x4142ED9C'u32, 0xA4315C11'u32, 0x83323EC5'u32, 0xDFEF4636'u32, 0xA133C501'u32, 0xE9D3531C'u32, 0xEE353783'u32
  ]
  SBox4: array[256, uint32] = [
    0x9DB30420'u32, 0x1FB6E9DE'u32, 0xA7BE7BEF'u32, 0xD273A298'u32, 0x4A4F7BDB'u32, 0x64AD8C57'u32, 0x85510443'u32, 0xFA020ED1'u32,
    0x7E287AFF'u32, 0xE60FB663'u32, 0x095F35A1'u32, 0x79EBF120'u32, 0xFD059D43'u32, 0x6497B7B1'u32, 0xF3641F63'u32, 0x241E4ADF'u32,
    0x28147F5F'u32, 0x4FA2B8CD'u32, 0xC9430040'u32, 0x0CC32220'u32, 0xFDD30B30'u32, 0xC0A5374F'u32, 0x1D2D00D9'u32, 0x24147B15'u32,
    0xEE4D111A'u32, 0x0FCA5167'u32, 0x71FF904C'u32, 0x2D195FFE'u32, 0x1A05645F'u32, 0x0C13FEFE'u32, 0x081B08CA'u32, 0x05170121'u32,
    0x80530100'u32, 0xE83E5EFE'u32, 0xAC9AF4F8'u32, 0x7FE72701'u32, 0xD2B8EE5F'u32, 0x06DF4261'u32, 0xBB9E9B8A'u32, 0x7293EA25'u32,
    0xCE84FFDF'u32, 0xF5718801'u32, 0x3DD64B04'u32, 0xA26F263B'u32, 0x7ED48400'u32, 0x547EEBE6'u32, 0x446D4CA0'u32, 0x6CF3D6F5'u32,
    0x2649ABDF'u32, 0xAEA0C7F5'u32, 0x36338CC1'u32, 0x503F7E93'u32, 0xD3772061'u32, 0x11B638E1'u32, 0x72500E03'u32, 0xF80EB2BB'u32,
    0xABE0502E'u32, 0xEC8D77DE'u32, 0x57971E81'u32, 0xE14F6746'u32, 0xC9335400'u32, 0x6920318F'u32, 0x081DBB99'u32, 0xFFC304A5'u32,
    0x4D351805'u32, 0x7F3D5CE3'u32, 0xA6C866C6'u32, 0x5D5BCCA9'u32, 0xDAEC6FEA'u32, 0x9F926F91'u32, 0x9F46222F'u32, 0x3991467D'u32,
    0xA5BF6D8E'u32, 0x1143C44F'u32, 0x43958302'u32, 0xD0214EEB'u32, 0x022083B8'u32, 0x3FB6180C'u32, 0x18F8931E'u32, 0x281658E6'u32,
    0x26486E3E'u32, 0x8BD78A70'u32, 0x7477E4C1'u32, 0xB506E07C'u32, 0xF32D0A25'u32, 0x79098B02'u32, 0xE4EABB81'u32, 0x28123B23'u32,
    0x69DEAD38'u32, 0x1574CA16'u32, 0xDF871B62'u32, 0x211C40B7'u32, 0xA51A9EF9'u32, 0x0014377B'u32, 0x041E8AC8'u32, 0x09114003'u32,
    0xBD59E4D2'u32, 0xE3D156D5'u32, 0x4FE876D5'u32, 0x2F91A340'u32, 0x557BE8DE'u32, 0x00EAE4A7'u32, 0x0CE5C2EC'u32, 0x4DB4BBA6'u32,
    0xE756BDFF'u32, 0xDD3369AC'u32, 0xEC17B035'u32, 0x06572327'u32, 0x99AFC8B0'u32, 0x56C8C391'u32, 0x6B65811C'u32, 0x5E146119'u32,
    0x6E85CB75'u32, 0xBE07C002'u32, 0xC2325577'u32, 0x893FF4EC'u32, 0x5BBFC92D'u32, 0xD0EC3B25'u32, 0xB7801AB7'u32, 0x8D6D3B24'u32,
    0x20C763EF'u32, 0xC366A5FC'u32, 0x9C382880'u32, 0x0ACE3205'u32, 0xAAC9548A'u32, 0xECA1D7C7'u32, 0x041AFA32'u32, 0x1D16625A'u32,
    0x6701902C'u32, 0x9B757A54'u32, 0x31D477F7'u32, 0x9126B031'u32, 0x36CC6FDB'u32, 0xC70B8B46'u32, 0xD9E66A48'u32, 0x56E55A79'u32,
    0x026A4CEB'u32, 0x52437EFF'u32, 0x2F8F76B4'u32, 0x0DF980A5'u32, 0x8674CDE3'u32, 0xEDDA04EB'u32, 0x17A9BE04'u32, 0x2C18F4DF'u32,
    0xB7747F9D'u32, 0xAB2AF7B4'u32, 0xEFC34D20'u32, 0x2E096B7C'u32, 0x1741A254'u32, 0xE5B6A035'u32, 0x213D42F6'u32, 0x2C1C7C26'u32,
    0x61C2F50F'u32, 0x6552DAF9'u32, 0xD2C231F8'u32, 0x25130F69'u32, 0xD8167FA2'u32, 0x0418F2C8'u32, 0x001A96A6'u32, 0x0D1526AB'u32,
    0x63315C21'u32, 0x5E0A72EC'u32, 0x49BAFEFD'u32, 0x187908D9'u32, 0x8D0DBD86'u32, 0x311170A7'u32, 0x3E9B640C'u32, 0xCC3E10D7'u32,
    0xD5CAD3B6'u32, 0x0CAEC388'u32, 0xF73001E1'u32, 0x6C728AFF'u32, 0x71EAE2A1'u32, 0x1F9AF36E'u32, 0xCFCBD12F'u32, 0xC1DE8417'u32,
    0xAC07BE6B'u32, 0xCB44A1D8'u32, 0x8B9B0F56'u32, 0x013988C3'u32, 0xB1C52FCA'u32, 0xB4BE31CD'u32, 0xD8782806'u32, 0x12A3A4E2'u32,
    0x6F7DE532'u32, 0x58FD7EB6'u32, 0xD01EE900'u32, 0x24ADFFC2'u32, 0xF4990FC5'u32, 0x9711AAC5'u32, 0x001D7B95'u32, 0x82E5E7D2'u32,
    0x109873F6'u32, 0x00613096'u32, 0xC32D9521'u32, 0xADA121FF'u32, 0x29908415'u32, 0x7FBB977F'u32, 0xAF9EB3DB'u32, 0x29C9ED2A'u32,
    0x5CE2A465'u32, 0xA730F32C'u32, 0xD0AA3FE8'u32, 0x8A5CC091'u32, 0xD49E2CE7'u32, 0x0CE454A9'u32, 0xD60ACD86'u32, 0x015F1919'u32,
    0x77079103'u32, 0xDEA03AF6'u32, 0x78A8565E'u32, 0xDEE356DF'u32, 0x21F05CBE'u32, 0x8B75E387'u32, 0xB3C50651'u32, 0xB8A5C3EF'u32,
    0xD8EEB6D2'u32, 0xE523BE77'u32, 0xC2154529'u32, 0x2F69EFDF'u32, 0xAFE67AFB'u32, 0xF470C4B2'u32, 0xF3E0EB5B'u32, 0xD6CC9876'u32,
    0x39E4460C'u32, 0x1FDA8538'u32, 0x1987832F'u32, 0xCA007367'u32, 0xA99144F8'u32, 0x296B299E'u32, 0x492FC295'u32, 0x9266BEAB'u32,
    0xB5676E69'u32, 0x9BD3DDDA'u32, 0xDF7E052F'u32, 0xDB25701C'u32, 0x1B5E51EE'u32, 0xF65324E6'u32, 0x6AFCE36C'u32, 0x0316CC04'u32,
    0x8644213E'u32, 0xB7DC59D0'u32, 0x7965291F'u32, 0xCCD6FD43'u32, 0x41823979'u32, 0x932BCDF6'u32, 0xB657C34D'u32, 0x4EDFD282'u32,
    0x7AE5290C'u32, 0x3CB9536B'u32, 0x851E20FE'u32, 0x9833557E'u32, 0x13ECF0B0'u32, 0xD3FFB372'u32, 0x3F85C5C1'u32, 0x0AEF7ED2'u32
  ]
  # key generating masking constant table
  TM: array[24, array[8, uint32]] = [
   [0x5A827999'u32, 0xC95C653A'u32, 0x383650DB'u32, 0xA7103C7C'u32, 0x15EA281D'u32, 0x84C413BE'u32, 0xF39DFF5F'u32, 0x6277EB00'u32],
   [0xD151D6A1'u32, 0x402BC242'u32, 0xAF05ADE3'u32, 0x1DDF9984'u32, 0x8CB98525'u32, 0xFB9370C6'u32, 0x6A6D5C67'u32, 0xD9474808'u32],
   [0x482133A9'u32, 0xB6FB1F4A'u32, 0x25D50AEB'u32, 0x94AEF68C'u32, 0x0388E22D'u32, 0x7262CDCE'u32, 0xE13CB96F'u32, 0x5016A510'u32],
   [0xBEF090B1'u32, 0x2DCA7C52'u32, 0x9CA467F3'u32, 0x0B7E5394'u32, 0x7A583F35'u32, 0xE9322AD6'u32, 0x580C1677'u32, 0xC6E60218'u32],
   [0x35BFEDB9'u32, 0xA499D95A'u32, 0x1373C4FB'u32, 0x824DB09C'u32, 0xF1279C3D'u32, 0x600187DE'u32, 0xCEDB737F'u32, 0x3DB55F20'u32],
   [0xAC8F4AC1'u32, 0x1B693662'u32, 0x8A432203'u32, 0xF91D0DA4'u32, 0x67F6F945'u32, 0xD6D0E4E6'u32, 0x45AAD087'u32, 0xB484BC28'u32],
   [0x235EA7C9'u32, 0x9238936A'u32, 0x01127F0B'u32, 0x6FEC6AAC'u32, 0xDEC6564D'u32, 0x4DA041EE'u32, 0xBC7A2D8F'u32, 0x2B541930'u32],
   [0x9A2E04D1'u32, 0x0907F072'u32, 0x77E1DC13'u32, 0xE6BBC7B4'u32, 0x5595B355'u32, 0xC46F9EF6'u32, 0x33498A97'u32, 0xA2237638'u32],
   [0x10FD61D9'u32, 0x7FD74D7A'u32, 0xEEB1391B'u32, 0x5D8B24BC'u32, 0xCC65105D'u32, 0x3B3EFBFE'u32, 0xAA18E79F'u32, 0x18F2D340'u32],
   [0x87CCBEE1'u32, 0xF6A6AA82'u32, 0x65809623'u32, 0xD45A81C4'u32, 0x43346D65'u32, 0xB20E5906'u32, 0x20E844A7'u32, 0x8FC23048'u32],
   [0xFE9C1BE9'u32, 0x6D76078A'u32, 0xDC4FF32B'u32, 0x4B29DECC'u32, 0xBA03CA6D'u32, 0x28DDB60E'u32, 0x97B7A1AF'u32, 0x06918D50'u32],
   [0x756B78F1'u32, 0xE4456492'u32, 0x531F5033'u32, 0xC1F93BD4'u32, 0x30D32775'u32, 0x9FAD1316'u32, 0x0E86FEB7'u32, 0x7D60EA58'u32],
   [0xEC3AD5F9'u32, 0x5B14C19A'u32, 0xC9EEAD3B'u32, 0x38C898DC'u32, 0xA7A2847D'u32, 0x167C701E'u32, 0x85565BBF'u32, 0xF4304760'u32],
   [0x630A3301'u32, 0xD1E41EA2'u32, 0x40BE0A43'u32, 0xAF97F5E4'u32, 0x1E71E185'u32, 0x8D4BCD26'u32, 0xFC25B8C7'u32, 0x6AFFA468'u32],
   [0xD9D99009'u32, 0x48B37BAA'u32, 0xB78D674B'u32, 0x266752EC'u32, 0x95413E8D'u32, 0x041B2A2E'u32, 0x72F515CF'u32, 0xE1CF0170'u32],
   [0x50A8ED11'u32, 0xBF82D8B2'u32, 0x2E5CC453'u32, 0x9D36AFF4'u32, 0x0C109B95'u32, 0x7AEA8736'u32, 0xE9C472D7'u32, 0x589E5E78'u32],
   [0xC7784A19'u32, 0x365235BA'u32, 0xA52C215B'u32, 0x14060CFC'u32, 0x82DFF89D'u32, 0xF1B9E43E'u32, 0x6093CFDF'u32, 0xCF6DBB80'u32],
   [0x3E47A721'u32, 0xAD2192C2'u32, 0x1BFB7E63'u32, 0x8AD56A04'u32, 0xF9AF55A5'u32, 0x68894146'u32, 0xD7632CE7'u32, 0x463D1888'u32],
   [0xB5170429'u32, 0x23F0EFCA'u32, 0x92CADB6B'u32, 0x01A4C70C'u32, 0x707EB2AD'u32, 0xDF589E4E'u32, 0x4E3289EF'u32, 0xBD0C7590'u32],
   [0x2BE66131'u32, 0x9AC04CD2'u32, 0x099A3873'u32, 0x78742414'u32, 0xE74E0FB5'u32, 0x5627FB56'u32, 0xC501E6F7'u32, 0x33DBD298'u32],
   [0xA2B5BE39'u32, 0x118FA9DA'u32, 0x8069957B'u32, 0xEF43811C'u32, 0x5E1D6CBD'u32, 0xCCF7585E'u32, 0x3BD143FF'u32, 0xAAAB2FA0'u32],
   [0x19851B41'u32, 0x885F06E2'u32, 0xF738F283'u32, 0x6612DE24'u32, 0xD4ECC9C5'u32, 0x43C6B566'u32, 0xB2A0A107'u32, 0x217A8CA8'u32],
   [0x90547849'u32, 0xFF2E63EA'u32, 0x6E084F8B'u32, 0xDCE23B2C'u32, 0x4BBC26CD'u32, 0xBA96126E'u32, 0x296FFE0F'u32, 0x9849E9B0'u32],
   [0x0723D551'u32, 0x75FDC0F2'u32, 0xE4D7AC93'u32, 0x53B19834'u32, 0xC28B83D5'u32, 0x31656F76'u32, 0xA03F5B17'u32, 0x0F1946B8'u32]
  ]
  # key generating rotate constant table
  TR: array[4, array[8, uint8]] = [
   [0x13'u8, 0x04'u8, 0x15'u8, 0x06'u8, 0x17'u8, 0x08'u8, 0x19'u8, 0x0A'u8],
   [0x1B'u8, 0x0C'u8, 0x1D'u8, 0x0E'u8, 0x1F'u8, 0x10'u8, 0x01'u8, 0x12'u8],
   [0x03'u8, 0x14'u8, 0x05'u8, 0x16'u8, 0x07'u8, 0x18'u8, 0x09'u8, 0x1A'u8],
   [0x0B'u8, 0x1C'u8, 0x0D'u8, 0x1E'u8, 0x0F'u8, 0x00'u8, 0x11'u8, 0x02'u8]
  ]

  # information constant
  CAST256_BLOCK_SIZE*: int = 16
  CAST256_128_KEY_SIZE*: int = 16
  CAST256_160_KEY_SIZE*: int = 20
  CAST256_192_KEY_SIZE*: int = 24
  CAST256_224_KEY_SIZE*: int = 28
  CAST256_256_KEY_SIZE*: int = 32
  CAST256_ROUND_NUMBER*: int = 48

type
  # CAST256 generic context
  CAST256Ctx*[keyBits: static int] = object
    rotateSubKey*: array[48, uint8]
    maskingSubKey*: array[48, uint32]

  # CAST256 128/160/192/224/256 context : declare by CAST256 generic context
  CAST256_128Ctx* {.exportc: "CAST256_128Ctx", completeStruct.} = CAST256Ctx[128]
  CAST256_160Ctx* {.exportc: "CAST256_160Ctx", completeStruct.} = CAST256Ctx[160]
  CAST256_192Ctx* {.exportc: "CAST256_192Ctx", completeStruct.} = CAST256Ctx[192]
  CAST256_224Ctx* {.exportc: "CAST256_224Ctx", completeStruct.} = CAST256Ctx[224]
  CAST256_256Ctx* {.exportc: "CAST256_256Ctx", completeStruct.} = CAST256Ctx[256]

# referencing SBox 1 ~ 4
template S1(a: uint32, b: int): uint32 =
  SBox1[int((a shr (8 * b)) and 0xFF)]

template S2(a: uint32, b: int): uint32 =
  SBox2[int((a shr (8 * b)) and 0xFF)]

template S3(a: uint32, b: int): uint32 =
  SBox3[int((a shr (8 * b)) and 0xFF)]

template S4(a: uint32, b: int): uint32 =
  SBox4[int((a shr (8 * b)) and 0xFF)]

# round template : F1 ~ F3
template F1(y: var uint32, x: uint32, rotate: uint8, masking: uint32): void {.autoSizeOpt.} =
  var temp: uint32 = masking + x
  temp = rotateLeftBits(temp, rotate)
  y = y xor ((S1(temp, 3) xor S2(temp, 2)) - S3(temp, 1) + S4(temp, 0))

template F2(y: var uint32, x: uint32, rotate: uint8, masking: uint32): void {.autoSizeOpt.} =
  var temp: uint32 = masking xor x
  temp = rotateLeftBits(temp, rotate)
  y = y xor (((S1(temp, 3) - S2(temp, 2)) + S3(temp, 1)) xor S4(temp, 0))

template F3(y: var uint32, x: uint32, rotate: uint8, masking: uint32): void {.autoSizeOpt.} =
  var temp: uint32 = masking - x
  temp = rotateLeftBits(temp, rotate)
  y = y xor (((S1(temp, 3) + S2(temp, 2)) xor S3(temp, 1)) - S4(temp, 0))

# quadratic round template : Q1 ~ Q2
template Q1(a, b, c, d: var uint32, rotate: slicearray[4, uint8], masking: slicearray[4, uint32]): void {.autoSizeOpt.} =
  F1(c, d, rotate[0], masking[0])
  F2(b, c, rotate[1], masking[1])
  F3(a, b, rotate[2], masking[2])
  F1(d, a, rotate[3], masking[3])

template Q2(a, b, c, d: var uint32, rotate: slicearray[4, uint8], masking: slicearray[4, uint32]): void {.autoSizeOpt.} =
  F1(d, a, rotate[3], masking[3])
  F3(a, b, rotate[2], masking[2])
  F2(b, c, rotate[1], masking[1])
  F1(c, d, rotate[0], masking[0])

# key scheduling round template
template W(a, b, c, d, e, f, g, h: var uint32, rotate: slicearray[8, uint8], masking: slicearray[8, uint32]): void {.autoSizeOpt.} =
  F1(g, h, rotate[0], masking[0])
  F2(f, g, rotate[1], masking[1])
  F3(e, f, rotate[2], masking[2])
  F1(d, e, rotate[3], masking[3])
  F2(c, d, rotate[4], masking[4])
  F3(b, c, rotate[5], masking[5])
  F1(a, b, rotate[6], masking[6])
  F2(h, a, rotate[7], masking[7])

# CAST256 init core
template cast256InitC*[K: static int](ctx: ptr CAST256Ctx[K], key: slicearray[K div 8, uint8]): void {.autoSizeOpt.} =
  # declaring temporary registers
  var a, b, c, d, e, f, g, h: uint32
  # initialising to 0
  a = 0; b = 0; c = 0; d = 0; e = 0; f = 0; g = 0; h = 0

  # loading key into temporary registers
  when K == 128:
    fromBytesBE(key.toSliceArray(0, 3), a)
    fromBytesBE(key.toSliceArray(4, 7), b)
    fromBytesBE(key.toSliceArray(8, 11), c)
    fromBytesBE(key.toSliceArray(12, 15), d)
  elif K == 160:
    fromBytesBE(key.toSliceArray(0, 3), a)
    fromBytesBE(key.toSliceArray(4, 7), b)
    fromBytesBE(key.toSliceArray(8, 11), c)
    fromBytesBE(key.toSliceArray(12, 15), d)
    fromBytesBE(key.toSliceArray(16, 19), e)
  elif K == 192:
    fromBytesBE(key.toSliceArray(0, 3), a)
    fromBytesBE(key.toSliceArray(4, 7), b)
    fromBytesBE(key.toSliceArray(8, 11), c)
    fromBytesBE(key.toSliceArray(12, 15), d)
    fromBytesBE(key.toSliceArray(16, 19), e)
    fromBytesBE(key.toSliceArray(20, 23), f)
  elif K == 224:
    fromBytesBE(key.toSliceArray(0, 3), a)
    fromBytesBE(key.toSliceArray(4, 7), b)
    fromBytesBE(key.toSliceArray(8, 11), c)
    fromBytesBE(key.toSliceArray(12, 15), d)
    fromBytesBE(key.toSliceArray(16, 19), e)
    fromBytesBE(key.toSliceArray(20, 23), f)
    fromBytesBE(key.toSliceArray(24, 27), g)
  elif K == 256:
    fromBytesBE(key.toSliceArray(0, 3), a)
    fromBytesBE(key.toSliceArray(4, 7), b)
    fromBytesBE(key.toSliceArray(8, 11), c)
    fromBytesBE(key.toSliceArray(12, 15), d)
    fromBytesBE(key.toSliceArray(16, 19), e)
    fromBytesBE(key.toSliceArray(20, 23), f)
    fromBytesBE(key.toSliceArray(24, 27), g)
    fromBytesBE(key.toSliceArray(28, 31), h)

  # key scheduling logic : unrolled
  for i in static(0 ..< 12):
    W(a, b, c, d, e, f, g, h, toSliceArray(TR[(2 * i) mod 4], 0, 7), toSliceArray(TM[2 * i], 0, 7))
    W(a, b, c, d, e, f, g, h, toSliceArray(TR[(2 * i + 1) mod 4], 0, 7), toSliceArray(TM[2 * i + 1], 0, 7))

    ctx.rotateSubKey[i * 4 + 0] = uint8(a and 0x1F)
    ctx.rotateSubKey[i * 4 + 1] = uint8(c and 0x1F)
    ctx.rotateSubKey[i * 4 + 2] = uint8(e and 0x1F)
    ctx.rotateSubKey[i * 4 + 3] = uint8(g and 0x1F)

    ctx.maskingSubKey[i * 4 + 0] = h
    ctx.maskingSubKey[i * 4 + 1] = f
    ctx.maskingSubKey[i * 4 + 2] = d
    ctx.maskingSubKey[i * 4 + 3] = b

# CAST256 encrypt core
template cast256EncryptC(ctx: CAST256Ctx, input, output: slicearray[16, uint8]): void {.autoSizeOpt.} =
  # declaring temporary registers
  var a, b, c, d: uint32
  
  # loading state into temporary registers
  fromBytesBE(input.toSliceArray(0, 3), a)
  fromBytesBE(input.toSliceArray(4, 7), b)
  fromBytesBE(input.toSliceArray(8, 11), c)
  fromBytesBE(input.toSliceArray(12, 15), d)

  # Q1 round loop : unrolled
  for i in static(0 ..< 6):
    Q1(a, b, c, d, toSliceArray(ctx.rotateSubKey, i * 4, i * 4 + 3, 4), toSliceArray(ctx.maskingSubKey, i * 4, i * 4 + 3, 4))

  # Q2 round loop : unrolled
  for i in static(6 ..< 12):
    Q2(a, b, c, d, toSliceArray(ctx.rotateSubKey, i * 4, i * 4 + 3, 4), toSliceArray(ctx.maskingSubKey, i * 4, i * 4 + 3, 4))

  # storing state to memory
  toBytesBE(a, output.toSliceArray(0, 3))
  toBytesBE(b, output.toSliceArray(4, 7))
  toBytesBE(c, output.toSliceArray(8, 11))
  toBytesBE(d, output.toSliceArray(12, 15))

# CAST256 decrypt core
template cast256DecryptC(ctx: CAST256Ctx, input, output: slicearray[16, uint8]): void {.autoSizeOpt.} =
  # declaring temporary registers
  var a, b, c, d: uint32
  
  # loading state into temporary registers
  fromBytesBE(input.toSliceArray(0, 3), a)
  fromBytesBE(input.toSliceArray(4, 7), b)
  fromBytesBE(input.toSliceArray(8, 11), c)
  fromBytesBE(input.toSliceArray(12, 15), d)

  # Q1 round loop : unrolled
  for i in countdown(11, 6):
    Q1(a, b, c, d, toSliceArray(ctx.rotateSubKey, i * 4, i * 4 + 3, 4), toSliceArray(ctx.maskingSubKey, i * 4, i * 4 + 3, 4))

  # Q2 round loop : unrolled
  for i in countdown(5, 0):
    Q2(a, b, c, d, toSliceArray(ctx.rotateSubKey, i * 4, i * 4 + 3, 4), toSliceArray(ctx.maskingSubKey, i * 4, i * 4 + 3, 4))

  # storing state to memory
  toBytesBE(a, output.toSliceArray(0, 3))
  toBytesBE(b, output.toSliceArray(4, 7))
  toBytesBE(c, output.toSliceArray(8, 11))
  toBytesBE(d, output.toSliceArray(12, 15))

# export wrappers
when defined(templateOpt):
  # 128
  template cast256_128Init*(ctx: var CAST256_128Ctx, key: array[16, uint8]): void =
    cast256InitC(addr ctx, key.toSliceArray(0, 15))
  template cast256_128Init*(ctx: var CAST256_128Ctx, key: openArray[uint8]): void =
    cast256InitC(addr ctx, key.toSliceArray(0, 15))
  template cast256_128Init*(ctx: var CAST256_128Ctx, key: slicearray[16, uint8]): void =
    cast256InitC(addr ctx, key)
  template cast256_128Init*(ctx: ptr CAST256_128Ctx, key: ptr array[16, uint8]): void =
    cast256InitC(ctx, key.toSliceArray(0, 15))

  template cast256_128Encrypt*(ctx: CAST256_128Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template cast256_128Encrypt*(ctx: CAST256_128Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template cast256_128Encrypt*(ctx: CAST256_128Ctx, input, output: slicearray[16, uint8]): void =
    cast256EncryptC(ctx, input, output)
  template cast256_128Encrypt*(ctx: CAST256_128Ctx, input, output: ptr array[16, uint8]): void =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template cast256_128Decrypt*(ctx: CAST256_128Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template cast256_128Decrypt*(ctx: CAST256_128Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template cast256_128Decrypt*(ctx: CAST256_128Ctx, input, output: slicearray[16, uint8]): void =
    cast256DecryptC(ctx, input, output)
  template cast256_128Decrypt*(ctx: CAST256_128Ctx, input, output: ptr array[16, uint8]): void =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  # 160
  template cast256_160Init*(ctx: var CAST256_160Ctx, key: array[20, uint8]): void =
    cast256InitC(addr ctx, key.toSliceArray(0, 19))
  template cast256_160Init*(ctx: var CAST256_160Ctx, key: openArray[uint8]): void =
    cast256InitC(addr ctx, key.toSliceArray(0, 19))
  template cast256_160Init*(ctx: var CAST256_160Ctx, key: slicearray[20, uint8]): void =
    cast256InitC(addr ctx, key)
  template cast256_160Init*(ctx: ptr CAST256_160Ctx, key: ptr array[20, uint8]): void =
    cast256InitC(ctx, key.toSliceArray(0, 19))

  template cast256_160Encrypt*(ctx: CAST256_160Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template cast256_160Encrypt*(ctx: CAST256_160Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template cast256_160Encrypt*(ctx: CAST256_160Ctx, input, output: slicearray[16, uint8]): void =
    cast256EncryptC(ctx, input, output)
  template cast256_160Encrypt*(ctx: CAST256_160Ctx, input, output: ptr array[16, uint8]): void =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template cast256_160Decrypt*(ctx: CAST256_160Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template cast256_160Decrypt*(ctx: CAST256_160Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template cast256_160Decrypt*(ctx: CAST256_160Ctx, input, output: slicearray[16, uint8]): void =
    cast256DecryptC(ctx, input, output)
  template cast256_160Decrypt*(ctx: CAST256_160Ctx, input, output: ptr array[16, uint8]): void =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  # 192
  template cast256_192Init*(ctx: var CAST256_192Ctx, key: array[24, uint8]): void =
    cast256InitC(addr ctx, key.toSliceArray(0, 23))
  template cast256_192Init*(ctx: var CAST256_192Ctx, key: openArray[uint8]): void =
    cast256InitC(addr ctx, key.toSliceArray(0, 23))
  template cast256_192Init*(ctx: var CAST256_192Ctx, key: slicearray[24, uint8]): void =
    cast256InitC(addr ctx, key)
  template cast256_192Init*(ctx: ptr CAST256_192Ctx, key: ptr array[24, uint8]): void =
    cast256InitC(ctx, key.toSliceArray(0, 23))

  template cast256_192Encrypt*(ctx: CAST256_192Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template cast256_192Encrypt*(ctx: CAST256_192Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template cast256_192Encrypt*(ctx: CAST256_192Ctx, input, output: slicearray[16, uint8]): void =
    cast256EncryptC(ctx, input, output)
  template cast256_192Encrypt*(ctx: CAST256_192Ctx, input, output: ptr array[16, uint8]): void =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template cast256_192Decrypt*(ctx: CAST256_192Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template cast256_192Decrypt*(ctx: CAST256_192Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template cast256_192Decrypt*(ctx: CAST256_192Ctx, input, output: slicearray[16, uint8]): void =
    cast256DecryptC(ctx, input, output)
  template cast256_192Decrypt*(ctx: CAST256_192Ctx, input, output: ptr array[16, uint8]): void =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  # 224
  template cast256_224Init*(ctx: var CAST256_224Ctx, key: array[28, uint8]): void =
    cast256InitC(addr ctx, key.toSliceArray(0, 27))
  template cast256_224Init*(ctx: var CAST256_224Ctx, key: openArray[uint8]): void =
    cast256InitC(addr ctx, key.toSliceArray(0, 27))
  template cast256_224Init*(ctx: var CAST256_224Ctx, key: slicearray[28, uint8]): void =
    cast256InitC(addr ctx, key)
  template cast256_224Init*(ctx: ptr CAST256_224Ctx, key: ptr array[28, uint8]): void =
    cast256InitC(ctx, key.toSliceArray(0, 27))

  template cast256_224Encrypt*(ctx: CAST256_224Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template cast256_224Encrypt*(ctx: CAST256_224Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template cast256_224Encrypt*(ctx: CAST256_224Ctx, input, output: slicearray[16, uint8]): void =
    cast256EncryptC(ctx, input, output)
  template cast256_224Encrypt*(ctx: CAST256_224Ctx, input, output: ptr array[16, uint8]): void =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template cast256_224Decrypt*(ctx: CAST256_224Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template cast256_224Decrypt*(ctx: CAST256_224Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template cast256_224Decrypt*(ctx: CAST256_224Ctx, input, output: slicearray[16, uint8]): void =
    cast256DecryptC(ctx, input, output)
  template cast256_224Decrypt*(ctx: CAST256_224Ctx, input, output: ptr array[16, uint8]): void =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  # 256
  template cast256_256Init*(ctx: var CAST256_256Ctx, key: array[32, uint8]): void =
    cast256InitC(addr ctx, key.toSliceArray(0, 31))
  template cast256_256Init*(ctx: var CAST256_256Ctx, key: openArray[uint8]): void =
    cast256InitC(addr ctx, key.toSliceArray(0, 31))
  template cast256_256Init*(ctx: var CAST256_256Ctx, key: slicearray[32, uint8]): void =
    cast256InitC(addr ctx, key)
  template cast256_256Init*(ctx: ptr CAST256_256Ctx, key: ptr array[32, uint8]): void =
    cast256InitC(ctx, key.toSliceArray(0, 31))

  template cast256_256Encrypt*(ctx: CAST256_256Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template cast256_256Encrypt*(ctx: CAST256_256Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template cast256_256Encrypt*(ctx: CAST256_256Ctx, input, output: slicearray[16, uint8]): void =
    cast256EncryptC(ctx, input, output)
  template cast256_256Encrypt*(ctx: CAST256_256Ctx, input, output: ptr array[16, uint8]): void =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template cast256_256Decrypt*(ctx: CAST256_256Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template cast256_256Decrypt*(ctx: CAST256_256Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template cast256_256Decrypt*(ctx: CAST256_256Ctx, input, output: slicearray[16, uint8]): void =
    cast256DecryptC(ctx, input, output)
  template cast256_256Decrypt*(ctx: CAST256_256Ctx, input, output: ptr array[16, uint8]): void =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
else:
  # 128
  proc cast256_128Init*(ctx: var CAST256_128Ctx, key: array[16, uint8]): void =
    cast256InitC(addr ctx, key.toSliceArray(0, 15))
  proc cast256_128Init*(ctx: var CAST256_128Ctx, key: openArray[uint8]): void =
    cast256InitC(addr ctx, key.toSliceArray(0, 15))
  proc cast256_128Init*(ctx: var CAST256_128Ctx, key: slicearray[16, uint8]): void =
    cast256InitC(addr ctx, key)
  proc cast256_128Init*(ctx: ptr CAST256_128Ctx, key: ptr array[16, uint8]): void {.exportc: "cast256_128Init", cdecl.} =
    cast256InitC(ctx, key.toSliceArray(0, 15))

  proc cast256_128Encrypt*(ctx: CAST256_128Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc cast256_128Encrypt*(ctx: CAST256_128Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc cast256_128Encrypt*(ctx: CAST256_128Ctx, input, output: slicearray[16, uint8]): void =
    cast256EncryptC(ctx, input, output)
  proc cast256_128Encrypt*(ctx: CAST256_128Ctx, input, output: ptr array[16, uint8]): void {.exportc: "cast256_128Encrypt", cdecl.} =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc cast256_128Decrypt*(ctx: CAST256_128Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc cast256_128Decrypt*(ctx: CAST256_128Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc cast256_128Decrypt*(ctx: CAST256_128Ctx, input, output: slicearray[16, uint8]): void =
    cast256DecryptC(ctx, input, output)
  proc cast256_128Decrypt*(ctx: CAST256_128Ctx, input, output: ptr array[16, uint8]): void {.exportc: "cast256_128Decrypt", cdecl.} =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  # 160
  proc cast256_160Init*(ctx: var CAST256_160Ctx, key: array[20, uint8]): void =
    cast256InitC(addr ctx, key.toSliceArray(0, 19))
  proc cast256_160Init*(ctx: var CAST256_160Ctx, key: openArray[uint8]): void =
    cast256InitC(addr ctx, key.toSliceArray(0, 19))
  proc cast256_160Init*(ctx: var CAST256_160Ctx, key: slicearray[20, uint8]): void =
    cast256InitC(addr ctx, key)
  proc cast256_160Init*(ctx: ptr CAST256_160Ctx, key: ptr array[20, uint8]): void {.exportc: "cast256_160Init", cdecl.} =
    cast256InitC(ctx, key.toSliceArray(0, 19))

  proc cast256_160Encrypt*(ctx: CAST256_160Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc cast256_160Encrypt*(ctx: CAST256_160Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc cast256_160Encrypt*(ctx: CAST256_160Ctx, input, output: slicearray[16, uint8]): void =
    cast256EncryptC(ctx, input, output)
  proc cast256_160Encrypt*(ctx: CAST256_160Ctx, input, output: ptr array[16, uint8]): void {.exportc: "cast256_160Encrypt", cdecl.} =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc cast256_160Decrypt*(ctx: CAST256_160Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc cast256_160Decrypt*(ctx: CAST256_160Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc cast256_160Decrypt*(ctx: CAST256_160Ctx, input, output: slicearray[16, uint8]): void =
    cast256DecryptC(ctx, input, output)
  proc cast256_160Decrypt*(ctx: CAST256_160Ctx, input, output: ptr array[16, uint8]): void {.exportc: "cast256_160Decrypt", cdecl.} =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  # 192
  proc cast256_192Init*(ctx: var CAST256_192Ctx, key: array[24, uint8]): void =
    cast256InitC(addr ctx, key.toSliceArray(0, 23))
  proc cast256_192Init*(ctx: var CAST256_192Ctx, key: openArray[uint8]): void =
    cast256InitC(addr ctx, key.toSliceArray(0, 23))
  proc cast256_192Init*(ctx: var CAST256_192Ctx, key: slicearray[24, uint8]): void =
    cast256InitC(addr ctx, key)
  proc cast256_192Init*(ctx: ptr CAST256_192Ctx, key: ptr array[24, uint8]): void {.exportc: "cast256_192Init", cdecl.} =
    cast256InitC(ctx, key.toSliceArray(0, 23))

  proc cast256_192Encrypt*(ctx: CAST256_192Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc cast256_192Encrypt*(ctx: CAST256_192Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc cast256_192Encrypt*(ctx: CAST256_192Ctx, input, output: slicearray[16, uint8]): void =
    cast256EncryptC(ctx, input, output)
  proc cast256_192Encrypt*(ctx: CAST256_192Ctx, input, output: ptr array[16, uint8]): void {.exportc: "cast256_192Encrypt", cdecl.} =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc cast256_192Decrypt*(ctx: CAST256_192Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc cast256_192Decrypt*(ctx: CAST256_192Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc cast256_192Decrypt*(ctx: CAST256_192Ctx, input, output: slicearray[16, uint8]): void =
    cast256DecryptC(ctx, input, output)
  proc cast256_192Decrypt*(ctx: CAST256_192Ctx, input, output: ptr array[16, uint8]): void {.exportc: "cast256_192Decrypt", cdecl.} =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  # 224
  proc cast256_224Init*(ctx: var CAST256_224Ctx, key: array[28, uint8]): void =
    cast256InitC(addr ctx, key.toSliceArray(0, 27))
  proc cast256_224Init*(ctx: var CAST256_224Ctx, key: openArray[uint8]): void =
    cast256InitC(addr ctx, key.toSliceArray(0, 27))
  proc cast256_224Init*(ctx: var CAST256_224Ctx, key: slicearray[28, uint8]): void =
    cast256InitC(addr ctx, key)
  proc cast256_224Init*(ctx: ptr CAST256_224Ctx, key: ptr array[28, uint8]): void {.exportc: "cast256_224Init", cdecl.} =
    cast256InitC(ctx, key.toSliceArray(0, 27))

  proc cast256_224Encrypt*(ctx: CAST256_224Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc cast256_224Encrypt*(ctx: CAST256_224Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc cast256_224Encrypt*(ctx: CAST256_224Ctx, input, output: slicearray[16, uint8]): void =
    cast256EncryptC(ctx, input, output)
  proc cast256_224Encrypt*(ctx: CAST256_224Ctx, input, output: ptr array[16, uint8]): void {.exportc: "cast256_224Encrypt", cdecl.} =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc cast256_224Decrypt*(ctx: CAST256_224Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc cast256_224Decrypt*(ctx: CAST256_224Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc cast256_224Decrypt*(ctx: CAST256_224Ctx, input, output: slicearray[16, uint8]): void =
    cast256DecryptC(ctx, input, output)
  proc cast256_224Decrypt*(ctx: CAST256_224Ctx, input, output: ptr array[16, uint8]): void {.exportc: "cast256_224Decrypt", cdecl.} =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  # 256
  proc cast256_256Init*(ctx: var CAST256_256Ctx, key: array[32, uint8]): void =
    cast256InitC(addr ctx, key.toSliceArray(0, 31))
  proc cast256_256Init*(ctx: var CAST256_256Ctx, key: openArray[uint8]): void =
    cast256InitC(addr ctx, key.toSliceArray(0, 31))
  proc cast256_256Init*(ctx: var CAST256_256Ctx, key: slicearray[32, uint8]): void =
    cast256InitC(addr ctx, key)
  proc cast256_256Init*(ctx: ptr CAST256_256Ctx, key: ptr array[32, uint8]): void {.exportc: "cast256_256Init", cdecl.} =
    cast256InitC(ctx, key.toSliceArray(0, 31))

  proc cast256_256Encrypt*(ctx: CAST256_256Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc cast256_256Encrypt*(ctx: CAST256_256Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc cast256_256Encrypt*(ctx: CAST256_256Ctx, input, output: slicearray[16, uint8]): void =
    cast256EncryptC(ctx, input, output)
  proc cast256_256Encrypt*(ctx: CAST256_256Ctx, input, output: ptr array[16, uint8]): void {.exportc: "cast256_256Encrypt", cdecl.} =
    cast256EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc cast256_256Decrypt*(ctx: CAST256_256Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc cast256_256Decrypt*(ctx: CAST256_256Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc cast256_256Decrypt*(ctx: CAST256_256Ctx, input, output: slicearray[16, uint8]): void =
    cast256DecryptC(ctx, input, output)
  proc cast256_256Decrypt*(ctx: CAST256_256Ctx, input, output: ptr array[16, uint8]): void {.exportc: "cast256_256Decrypt", cdecl.} =
    cast256DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
