
rule ELASTIC_Linux_Trojan_Pornoasset_927F314F : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Pornoasset (Linux.Trojan.Pornoasset)"
		author = "Elastic Security"
		id = "927f314f-2cbb-4f87-b75c-9aa5ef758599"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Pornoasset.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d653598df857535c354ba21d96358d4767d6ada137ee32ce5eb4972363b35f93"
		logic_hash = "7267375346c1628e04c8272c24bde04a5d6ae2b420f64dfe58657cfc3eecc0e7"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7214d3132fc606482e3f6236d291082a3abc0359c80255048045dba6e60ec7bf"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C3 D3 CB D3 C3 48 31 C3 48 0F AF F0 48 0F AF F0 48 0F AF F0 48 }

	condition:
		all of them
}