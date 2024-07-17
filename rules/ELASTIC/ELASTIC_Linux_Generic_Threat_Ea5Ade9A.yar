rule ELASTIC_Linux_Generic_Threat_Ea5Ade9A : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "ea5ade9a-101e-49df-b0e8-45a04320950b"
		date = "2024-01-17"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L22-L40"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d75189d883b739d9fe558637b1fab7f41e414937a8bae7a9d58347c223a1fcaa"
		logic_hash = "12a9b5e54d6d528ecb559b6e2ea3aa72effa7f0efbf2c33581a4efedc292e4c1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "fedf3b94c22a1dab3916b7bc6a1b88768c0debd6d628b78d8a6610b636f3c652"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 55 89 E5 53 8B 5D 08 B8 0D 00 00 00 CD 80 8B 5D FC 89 EC 5D C3 55 89 E5 53 8B 5D 08 B8 2D 00 00 00 CD 80 8B 5D FC 89 EC 5D C3 55 89 E5 53 8B 5D 08 8B 4D 0C B8 6C 00 00 00 CD 80 8B 5D FC 89 EC }

	condition:
		all of them
}