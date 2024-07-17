rule SIGNATURE_BASE_APT_FIN7_Sample_Aug18_1 : FILE
{
	meta:
		description = "Detects FIN7 samples mentioned in FireEye report"
		author = "Florian Roth (Nextron Systems)"
		id = "0fdd98e8-7536-5159-8085-da7388e5fff2"
		date = "2018-08-01"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_fin7.yar#L66-L93"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5ff078f8cb93a841b68521cfbc120b18952c7ff5b56ab2f3b0eebf63a10aa572"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a1e95ac1bb684186e9fb5c67f75c7c26ddc8b18ebfdaf061742ddf1675e17d55"
		hash2 = "dc645aae5d283fa175cf463a19615ed4d16b1d5238686245574d8a6a8b0fc8fa"
		hash3 = "eebbce171dab636c5ac0bf0fd14da0e216758b19c0ce2e5c572d7e6642d36d3d"

	strings:
		$s1 = "\\par var console=\\{\\};console.log=function()\\{\\};" ascii
		$s2 = "616e64792d7063" ascii
		$x1 = "0043003a005c00550073006500720073005c0061006e00640079005c004400650073006b0074006f0070005c0075006e00700072006f0074006500630074" ascii
		$x2 = "780065006300750074006500280022004f006e0020004500720072006f007200200052006500730075006d00650020004e006500780074003a0073006500" ascii
		$x3 = "\\par \\tab \\tab \\tab sh.Run \"powershell.exe -NoE -NoP -NonI -ExecutionPolicy Bypass -w Hidden -File \" & pToPSCb, 0, False" fullword ascii
		$x4 = "002e006c006e006b002d00000043003a005c00550073006500720073005c007400650073007400610064006d0069006e002e0054004500530054005c0044" ascii
		$x5 = "005c00550073006500720073005c005400450053005400410044007e0031002e005400450053005c0041007000700044006100740061005c004c006f0063" ascii
		$x6 = "6c00690063006100740069006f006e002200220029003a00650078006500630075007400650020007700700072006f0074006500630074002e0041006300" ascii
		$x7 = "7374656d33325c6d736874612e657865000023002e002e005c002e002e005c002e002e005c00570069006e0064006f00770073005c005300790073007400" ascii
		$x8 = "\\par \\tab \\tab sh.Run \"%comspec% /c tasklist >\"\"\" & tpath & \"\"\" 2>&1\", 0, true" fullword ascii
		$x9 = "00720079007b006500760061006c0028002700770061006c006c003d004700650074004f0062006a0065006300740028005c005c0027005c005c00270027" ascii
		$x10 = "006e00640079005c004400650073006b0074006f0070005c0075006e006c006f0063006b002e0064006f0063002e006c006e006b" ascii

	condition:
		uint16(0)==0x5c7b and filesize <3000KB and (1 of ($x*) or 2 of them )
}