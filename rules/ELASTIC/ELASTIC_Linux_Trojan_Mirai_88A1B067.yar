
rule ELASTIC_Linux_Trojan_Mirai_88A1B067 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "88a1b067-11d5-4128-b763-2d1747c95eef"
		date = "2021-06-28"
		modified = "2021-09-16"
		reference = "1a62db02343edda916cbbf463d8e07ec2ad4509fd0f15a5f6946d0ec6c332dd9"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1722-L1740"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "0755f1f974734ccd4ecc444217bf52ed306d1dc32c05841ba9ca6d259e1a147e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b32b42975297aed7cef72668ee272a5cfb753dce7813583f0c3ec91e52f8601f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 00 00 55 89 E5 0F B6 55 08 0F B6 45 0C C1 E2 18 C1 E0 10 }

	condition:
		all of them
}