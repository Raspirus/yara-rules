
rule ELASTIC_Linux_Trojan_Sshdoor_7C3Cfc62 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Sshdoor (Linux.Trojan.Sshdoor)"
		author = "Elastic Security"
		id = "7c3cfc62-aa90-4c28-b428-e2133a3f10f8"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Sshdoor.yar#L141-L159"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ee1f6dbea40d198e437e8c2ae81193472c89e41d1998bee071867dab1ce16b90"
		logic_hash = "da9804489f30b575d2b459f82570f5df07c1777f105cd373c4268f8a31fa4e43"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8085c47704b4d6cabad9d1dd48034dc224f725ba22a7872db50c709108bf575d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 55 48 8D 6F 50 53 49 89 FC 48 89 FB 48 83 EC 10 64 48 8B 04 25 28 00 }

	condition:
		all of them
}