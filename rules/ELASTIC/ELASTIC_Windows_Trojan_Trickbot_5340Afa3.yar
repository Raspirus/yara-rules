
rule ELASTIC_Windows_Trojan_Trickbot_5340Afa3 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Trickbot (Windows.Trojan.Trickbot)"
		author = "Elastic Security"
		id = "5340afa3-ff90-4f61-a1ac-aba1f32dd375"
		date = "2021-03-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L98-L115"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "8b9d3c978f0c4a04ee5b3446b990172206b17496036bc1cc04180ea7e9b99734"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7da4726ccda6a76d2da773d41f012763802d586f64a313c1c37733905ae9da81"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { E8 0C 89 5D F4 0F B7 DB 03 5D 08 66 83 F8 03 75 0A 8B 45 14 }

	condition:
		all of them
}