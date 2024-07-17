rule ELASTIC_Linux_Trojan_Mirai_0Eba3F5A : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "0eba3f5a-1aa8-4dc8-9f63-01bc4959792a"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1244-L1262"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2e4f89c76dfefd4b2bfd1cf0467ac0324026355723950d12d7ed51195fd998cf"
		logic_hash = "bcb2f1e1659102f39977fac43b119c58d6c72f828c3065e2318f671146e911da"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c0f4f9a93672bce63c9e3cfc389c73922c1c24a2db7728ad7ebc1d69b4db150f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C3 55 48 89 E5 48 83 EC 40 48 89 7D C8 89 F0 66 89 45 C4 C7 45 DC 01 00 }

	condition:
		all of them
}