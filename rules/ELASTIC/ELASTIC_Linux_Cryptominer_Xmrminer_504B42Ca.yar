rule ELASTIC_Linux_Cryptominer_Xmrminer_504B42Ca : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Xmrminer (Linux.Cryptominer.Xmrminer)"
		author = "Elastic Security"
		id = "504b42ca-00a7-4917-8bb1-1957838a1d27"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Xmrminer.yar#L81-L98"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "dd3ed5350e0229ac714178a30de28893c30708734faec329c776e189493cf930"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "265a3cb860e1f0ddafbe5658fa3a341d7419c89eecc350f8fc16e7a1e05a7673"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { D7 8B 04 8C 44 8D 50 FF 4C 89 04 C6 44 89 14 8C 75 D7 48 8B 2E 45 }

	condition:
		all of them
}