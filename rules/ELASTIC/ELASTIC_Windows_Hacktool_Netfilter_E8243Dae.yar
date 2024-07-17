rule ELASTIC_Windows_Hacktool_Netfilter_E8243Dae : FILE
{
	meta:
		description = "Detects Windows Hacktool Netfilter (Windows.Hacktool.NetFilter)"
		author = "Elastic Security"
		id = "e8243dae-33d9-4b54-8f4a-ba5cf5241767"
		date = "2022-04-04"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_NetFilter.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "760be95d4c04b10df89a78414facf91c0961020e80561eee6e2cb94b43b76510"
		logic_hash = "c551bd87e73f980d8836b13449490de5e639d768b72d9006d90969f3140b28e2"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "1542c32471f5d3f20beeb60c696085548d675f5d1cab1a0ef85a7060b01f0349"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "[NetFlt]:CTRL NDIS ModifyARP"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}