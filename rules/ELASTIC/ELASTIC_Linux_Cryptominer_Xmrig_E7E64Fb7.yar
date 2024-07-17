
rule ELASTIC_Linux_Cryptominer_Xmrig_E7E64Fb7 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Xmrig (Linux.Cryptominer.Xmrig)"
		author = "Elastic Security"
		id = "e7e64fb7-e07c-4184-86bd-db491a2a11e0"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Xmrig.yar#L61-L78"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "e325ac02c51526c5a36bdd6c2bcb3bee51f1214d78eff8048c8a1ae88334a9e8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "444240375f4b9c6948907c7e338764ac8221e5fcbbc2684bbd0a1102fef45e06"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 03 48 89 74 24 48 77 05 48 8B 5C C4 30 4C 8B 0A 48 8B 0F 48 8B }

	condition:
		all of them
}