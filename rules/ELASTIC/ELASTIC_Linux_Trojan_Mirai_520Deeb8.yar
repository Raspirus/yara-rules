rule ELASTIC_Linux_Trojan_Mirai_520Deeb8 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "520deeb8-cbc0-4225-8d23-adba5e040471"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L716-L733"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "671c17835f30cce1e5d68dbf3a73d340069b1b55a2ac42fc132c008cb2da622e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f4dfd1d76e07ff875eedfe0ef4f861bee1e4d8e66d68385f602f29cc35e30cca"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { ED 48 89 44 24 30 44 89 6C 24 10 7E 47 48 89 C1 44 89 E8 44 }

	condition:
		all of them
}