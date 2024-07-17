rule TRELLIX_ARC_Netwalker_Signed : FILE
{
	meta:
		description = "Rule to detect Netwalker ransomware digitally signed."
		author = "Marc Rivero | McAfee ATR Team"
		id = "6806b917-2e02-57e3-887a-b4c12db83653"
		date = "2020-03-30"
		modified = "2020-11-20"
		reference = "https://www.ccn-cert.cni.es/comunicacion-eventos/comunicados-ccn-cert/9802-publicado-un-informe-de-codigo-danino-sobre-netwalker.html"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_netwalker.yar#L30-L47"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "d78ed22771d7c93516375afb8fd2fd7baa40a357ec3c247939a10d11f80ae226"
		score = 75
		quality = 70
		tags = "FILE"
		note = "The rule will hit also some Dridex samples digitally signed"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "/CN=EWBTCAXQKUMDTHCXCZ" and pe.signatures[i].serial=="17:16:bb:93:fb:a9:a2:41:ba:a8:2e:c7:5e:ff:0c" or pe.signatures[i].thumbprint=="a4:28:e9:4a:61:3a:1f:cf:ff:08:bf:e7:61:51:64:31:1a:6f:87:bc")
}