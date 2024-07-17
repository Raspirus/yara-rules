rule ELASTIC_Linux_Ransomware_Gonnacry_53C3832D : FILE MEMORY
{
	meta:
		description = "Detects Linux Ransomware Gonnacry (Linux.Ransomware.Gonnacry)"
		author = "Elastic Security"
		id = "53c3832d-ceff-407d-920b-7b6442688fa9"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Ransomware_Gonnacry.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f5de75a6db591fe6bb6b656aa1dcfc8f7fe0686869c34192bfa4ec092554a4ac"
		logic_hash = "2b7453c4eb71b71e6a241f728b077a2ee63d988d55a64fedf61c34222799e262"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7d93c26c9e069af5cef964f5747104ba6d1d0d030a1f6b1c377355223c5359a1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 55 48 89 E5 48 83 EC 10 48 89 7D F8 EB 56 48 8B 45 F8 48 8B }

	condition:
		all of them
}