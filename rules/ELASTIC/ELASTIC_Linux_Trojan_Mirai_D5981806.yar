rule ELASTIC_Linux_Trojan_Mirai_D5981806 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "d5981806-0db8-4422-ad57-5d1c0f7464c3"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1621-L1639"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "784f2005853b5375efaf3995208e4611b81b8c52f67b6dc139fd9fec7b49d9dc"
		logic_hash = "e625323543aa5c8374a179dfa51c3f5be1446459c45fa7c7a27ae383cf0f551b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b0fd8632505252315ba551bb3680fa8dc51038be17609018bf9d92c3e1c43ede"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 3F 00 00 66 83 7C 24 38 FF 66 89 46 04 0F 85 EA }

	condition:
		all of them
}