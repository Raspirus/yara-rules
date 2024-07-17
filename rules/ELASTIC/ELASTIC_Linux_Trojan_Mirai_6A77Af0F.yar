
rule ELASTIC_Linux_Trojan_Mirai_6A77Af0F : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "6a77af0f-31fa-4793-82aa-10b065ba1ec0"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L813-L830"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "7d7623dfc1e16c7c02294607ddf46edd12cdc7d39a2b920d8711dc47c383731b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4e436f509e7e732e3d0326bcbdde555bba0653213ddf31b43cfdfbe16abb0016"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 31 D1 89 0F 48 83 C7 04 85 F6 7E 3B 44 89 C8 45 89 D1 45 89 C2 41 }

	condition:
		all of them
}