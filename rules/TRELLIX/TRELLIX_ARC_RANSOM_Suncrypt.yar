rule TRELLIX_ARC_RANSOM_Suncrypt : RANSOMWARE FILE
{
	meta:
		description = "Rule to detect SunCrypt ransomware"
		author = "McAfee ATR Team"
		id = "92655f3e-f8e4-5c9f-ae3f-0796bd31d660"
		date = "2020-10-02"
		modified = "2020-11-02"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_Suncrypt.yar#L1-L25"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "9f27c6c5bfe0d01ed517d55687bf699814679488f95ce4942306f09f39e29d85"
		score = 75
		quality = 70
		tags = "RANSOMWARE, FILE"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransomware:W32/Suncrypt"
		actor_type = "Cybercrime"
		actor_group = "Unknown"
		hash1 = "3090bff3d16b0b150444c3bfb196229ba0ab0b6b826fa306803de0192beddb80"
		hash2 = "63ba6db8c81c60dd9f1a0c7c4a4c51e2e56883f063509ed7b543ad7651fd8806"

	strings:
		$pattern = { 77??2F475263????78??58436463????77??7A??5263????78??5846534D5A4678??48475263??????6B??????4D5A4679??7A??5263????78??584C5163????7A??44475264??5778??58526163????30????475264??30????58556463????31????475264??73??6B??????63????32????4752646C73??6B??????38????32??5047526477??6A??5738????68????????41555039????496C46374931????46446F62????414146442F565169????????????5039????466D4A526669??????????64??63????4F6D38????414169??????????586F69??????????33????30????69????????????6F41444141414974??38????41554542516167??2F5665??4478??434A526679??6666????64??63????4F6D444141414169??????????33??69????????????77??33????2F33????2F33????36??49464141434478??7A??64667A??64??7A??64??6A??73??7A??2F34??454449584164??517A??4F74??69??????????5834??5558672F33????2F33????36??6E362F2F39????59584164??517A??4F73??69??????????33??69????????????554B30????69????????????30????5838????5830????5549554974??4446434C525268????????30??39????77??444A77??574C37495073??4D5A4634??62????65??70??6B??????73??4634??54475265??31????586C5963????35????????65????78??586F63????4636??2F47526570??78??5872??63????37475047526531??78??5875??4931????46446F534163????46442F565169????????????66??51616B??????52434C51416A??63????4C5252442F63????2F566679??78??434677??55454D38??????475368????????41496C462B????462B????4E454974??49496C49434974??454974??434974??454974??49414E494B496C4E39????4639????517A??5041514D6E44565976??555974??434974??434974??434974??494474??4E4855464D38????367A??4C525169??????????????6C72??51574466??68????????454D38??????6F74??434974??434974??434974??494374??4E496C4E2F5039??2F4974??435039????4F6A??2B????2F57566E4A77??574C37494873??41414141494E6C6C4143445A6141416733??514148554969??????????30??????44475266??75??6B??????4D5A4638????475266??73??6B??????4D5A4639????475266??6B??????33????5A462B????4752666B??????5867??73??4634??6E475265??79??6B??????4D5A4635????????65??68????????62????4635????????65??????????70??63????366E4C47526574??78??5873??4D5A4630????475264??70??6B??????73??4630??54475264??31????58565963????31????475264????78??585962????4632????47526470??78??5862????5A4633????475262????78??5739????5A4676??54475262??4478??58416463????77??4C475263????78??58445A63????78??37475263????78??5847554D5A4678??4C475263????78??584A5938????79??58475263??????6B??????38????7A??44475261526178??576C64??????70??584752616475??6B??????63????71??4847526170??78??5772??73??4672??6E47526131??????5775??38????72??2F475262????78??5778??38????73??58475262????78??5730??????4674??6E475262????78??5733????5A4675??434E5265??5136??4D46414142512F31????69????????????51554F677A??514141555039????496C466E4931????46446F4977??414146442F565169????????????6152516A??5877??5039????46442F565169????????????52434C514269????????????4932????502F2F2F31??????667A??565A434677??515A67??32????414142414855433677??4C526677??68????????2F2B????667A??31????46454974??434974??454974??4E4474??47484A4D69??????????414969??????????5838????36??6661414164??69??????????????6A??565978??2F31????68????????32????61414177??41434C5252434C514169??????????????74??454974??435039????5039????495045454974??45496C4249476F4561414177??41434C5252434C514169??????????????74??454974??435039????5039????495045454974??45496C42494974??45494E34??414231????74??454974??43476F49575776??42594E38????77??64??474C5252434C514169??????????????534A51534472??476F4561414177??41434C5252434C514169??????????????6F412F31????67??????69??????????456769??????????67????48554636??67??4141434C5252434C51416A??63????4C5252442F63????4C5252442F63????6F30????4141495045444974??454974??434974??454974??43412B??5352534E524167??69????????????38????73??69??????????6C462F4974??454974??43412B??51415935????????4F5774??2F4369??????????????45516130????4B4974??454974??454974??6D414E4D4168????????5838????74??454974??494974??6D414E4D416778??36??59424141434478??7A??73??64??6C4145414141417A??412B????50372F2F34??466C4D6E44565976??555974??434974??434974??45496C49424974??434974??42412B??414431????67??4164??517A??4F73??69??????????414569??????????6B??????67??????554969????????????4969??????????68????????4164??517A?? }

	condition:
		uint16(0)==0x6441 and all of them
}