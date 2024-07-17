rule ELASTIC_Linux_Trojan_Ladvix_Db41F9D2 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Ladvix (Linux.Trojan.Ladvix)"
		author = "Elastic Security"
		id = "db41f9d2-aa5c-4d26-b8ba-cece44eddca8"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Ladvix.yar#L1-L18"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "81642b4ff1b6488098f019c5e992fc942916bc6eb593006cf91e878ac41509d6"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d0aaa680e81f44cc555bf7799d33fce66f172563788afb2ad0fb16d3e460e8c6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C0 49 89 C4 74 45 45 85 ED 7E 26 48 89 C3 41 8D 45 FF 4D 8D 7C }

	condition:
		all of them
}