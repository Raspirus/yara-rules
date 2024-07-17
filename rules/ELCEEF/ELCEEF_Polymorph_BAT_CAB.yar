
rule ELCEEF_Polymorph_BAT_CAB : FILE
{
	meta:
		description = "Detects polymorphic BAT/CAB files self-extracting payload with extrac32.exe/extract.exe"
		author = "marcin@ulikowski.pl"
		id = "10a46120-beaf-5443-bc35-c6d9ef065bb4"
		date = "2024-04-10"
		modified = "2024-04-10"
		reference = "https://github.com/elceef/yara-rulz"
		source_url = "https://github.com/elceef/yara-rulz/blob/05834717d1464d5efce8ad9d688ff7b53886a0bb/rules/Suspicious_BAT.yara#L57-L72"
		license_url = "https://github.com/elceef/yara-rulz/blob/05834717d1464d5efce8ad9d688ff7b53886a0bb/LICENSE"
		logic_hash = "d29d488b0ebcfb485818c181ac674e3586aa1a41ab68185a1f1d3e49295ffbce"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "f1296b12925108a5d675a8b9c2033c0b749b121ae3b5a6a912ce4418daa06d99"

	strings:
		$extract = { 65 78 74 72 61 63 ( 33 32 | 74 ) 20 2f 79 20 22 25 7e 66 30 22 }

	condition:
		uint32be(0)==0x4d534346 and uint32(16)>80 and $extract in (48..80)
}