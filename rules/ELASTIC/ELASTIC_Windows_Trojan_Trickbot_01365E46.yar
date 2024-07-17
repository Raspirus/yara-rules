
rule ELASTIC_Windows_Trojan_Trickbot_01365E46 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Trickbot (Windows.Trojan.Trickbot)"
		author = "Elastic Security"
		id = "01365e46-c769-4c6e-913a-4d1e42948af2"
		date = "2021-03-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5c450d4be39caef1d9ec943f5dfeb6517047175fec166a52970c08cd1558e172"
		logic_hash = "4d61de2cb37e12f62326c1717f6ed44554f5d2aa7ede6033d0c988e5e64df54d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "98505c3418945c10bf4f50a183aa49bdbc7c1c306e98132ae3d0fc36e216f191"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 8B 43 28 4C 8B 53 18 4C 8B 5B 10 4C 8B 03 4C 8B 4B 08 89 44 24 38 48 89 4C 24 30 4C }

	condition:
		all of them
}