rule ELASTIC_Linux_Trojan_Sshdoor_32D9Fb1B : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Sshdoor (Linux.Trojan.Sshdoor)"
		author = "Elastic Security"
		id = "32d9fb1b-79d7-4bd1-bbe5-345550591367"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Sshdoor.yar#L121-L139"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ee1f6dbea40d198e437e8c2ae81193472c89e41d1998bee071867dab1ce16b90"
		logic_hash = "35ef4f3970484a46d705e6976a9932639d576717454b8e07ed24a72114d9c42d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "fa28250df6960ee54de7b0bacb437b543615a241267e34b5a422f231f5088f10"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 8B 04 25 28 00 00 00 48 89 44 24 08 31 C0 66 0F EF C0 48 85 F6 }

	condition:
		all of them
}