
rule ELASTIC_Linux_Trojan_Dofloo_29C12775 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Dofloo (Linux.Trojan.Dofloo)"
		author = "Elastic Security"
		id = "29c12775-b7e5-417d-9789-90b9bd4529dd"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Dofloo.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "88d826bac06c29e1b9024baaf90783e15d87d2a5c8c97426cbd5a70ae0f99461"
		logic_hash = "a8eb79fdf57811f4ffd5a7c5ec54cf46c06281f8cd4d677aec1ad168d6648a08"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "fbf49f0904e22c4d788f151096f9b1d80aa8c739b31705e6046d17029a6a7a4f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 2F 7E 49 00 64 80 49 00 34 7F 49 00 04 7F 49 00 24 80 49 }

	condition:
		all of them
}