
rule ELASTIC_Linux_Trojan_Mobidash_Bb4F7F39 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mobidash (Linux.Trojan.Mobidash)"
		author = "Elastic Security"
		id = "bb4f7f39-1f1c-4a2d-a480-3e1d2b6967b7"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mobidash.yar#L159-L177"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
		logic_hash = "33e8fcbb29cc38b4a8365845eb3a1488e13be964f7383b28a158a98fb259acb4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b7e96ff17a19ffcbfc87cdba3f86216271ff01c460ff7564f6af6b40c21a530b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 75 1F 48 8D 64 24 08 48 89 DF 5B 48 89 EA 4C 89 E1 4C 89 EE 5D }

	condition:
		all of them
}