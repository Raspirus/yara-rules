rule ELASTIC_Linux_Trojan_Gafgyt_D0C57A2E : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "d0c57a2e-c10c-436c-be13-50a269326cf2"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L674-L691"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "2ac51f0943d573fdc9a39837aeefd9158c27a4b3f35fbbb0a058a88392a53c14"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3ee7d3a33575ed3aa7431489a8fb18bf30cfd5d6c776066ab2a27f93303124b6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 07 0F B6 57 01 C1 E0 08 09 D0 89 06 0F BE 47 02 C1 E8 1F 89 }

	condition:
		all of them
}