
rule ELASTIC_Linux_Trojan_Rotajakiro_Fb24F399 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Rotajakiro (Linux.Trojan.Rotajakiro)"
		author = "Elastic Security"
		id = "fb24f399-d2bc-4cca-a3b8-4d924f11c83e"
		date = "2021-06-28"
		modified = "2021-09-16"
		reference = "023a7f9ed082d9dd7be6eba5942bfa77f8e618c2d15a8bc384d85223c5b91a0c"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Rotajakiro.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "be33fdda50ef0ea1a0cf45835cc2b7a805cecb3fff371ed6d93e01c2d477d867"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6b19a49c93a0d3eb380c78ca21ce4f4d2991c35e68d2b75e173dc25118ba2c20"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 41 56 41 55 41 54 49 89 FD 55 53 48 63 DE 48 83 EC 08 0F B6 17 80 }

	condition:
		all of them
}