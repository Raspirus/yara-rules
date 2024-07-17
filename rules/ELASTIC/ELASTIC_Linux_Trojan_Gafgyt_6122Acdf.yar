
rule ELASTIC_Linux_Trojan_Gafgyt_6122Acdf : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "6122acdf-1eef-45ea-83ea-699d21c2dc20"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L396-L413"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "140b32a8f2b7493b068e63a05b3d9baec6ec14c9f2062c7e760dde96335e29f1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "283275705c729be23d7dc75056388ecae00390bd25ee7b66b0cfc9b85feee212"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E8 B0 00 FC 8B 7D E8 F2 AE 89 C8 F7 D0 48 48 89 45 F8 EB 03 FF }

	condition:
		all of them
}