rule ELASTIC_Linux_Trojan_Dropperl_E2443Be5 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Dropperl (Linux.Trojan.Dropperl)"
		author = "Elastic Security"
		id = "e2443be5-da15-4af2-b090-bf5accf2a844"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Dropperl.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "aff94f915fc81d5a2649ebd7c21ec8a4c2fc0d622ec9b790b43cc49f7feb83da"
		logic_hash = "85733ff904cfa3eddaa4c4fbfc51c00494c3a3725e2eb722bbf33c82e7135336"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e49acaa476bd669b40ccc82a7d3a01e9c421e6709ecbfe8d0e24219677c96339"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 45 F0 75 DB EB 17 48 8B 45 F8 48 83 C0 08 48 8B 10 48 8B 45 F8 48 }

	condition:
		all of them
}