rule ELASTIC_Linux_Trojan_Mirai_7146E518 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "7146e518-f6f4-425d-bac8-b31edc0ac559"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L794-L811"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "374602254be1f5c1dbb00ad25d870722e03d674033dfcf953a2895e1f50c637d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "334ef623a8dadd33594e86caca1c95db060361c65bf366bacb9bc3d93ba90c4f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 85 82 11 79 AF 20 C2 7A 9E 18 6C A9 00 21 E2 6A C6 D5 59 B4 E8 }

	condition:
		all of them
}