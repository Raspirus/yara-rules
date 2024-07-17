
rule ELASTIC_Windows_Trojan_Protects_9F6Eaa90 : FILE
{
	meta:
		description = "Detects Windows Trojan Protects (Windows.Trojan.ProtectS)"
		author = "Elastic Security"
		id = "9f6eaa90-b3d4-4f0f-a81e-8010be0a6d36"
		date = "2022-04-04"
		modified = "2022-06-09"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_ProtectS.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c0330e072b7003f55a3153ac3e0859369b9c3e22779b113284e95ce1e2ce2099"
		logic_hash = "ddc8c97598b2d961dc51bdf2c7ab96abcec63824acd39b767bc175371844c1e5"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "46bf59901876794dcc338923076939d765d3ce7f14d784b9687fbc05461ed6b4"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\ProtectS.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}