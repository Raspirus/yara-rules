rule ELASTIC_Linux_Trojan_Merlin_C6097296 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Merlin (Linux.Trojan.Merlin)"
		author = "Elastic Security"
		id = "c6097296-c518-4541-99b2-e2f6d3e4610b"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Merlin.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d9955487f7d08f705e41a5ff848fb6f02d6c88286a52ec837b7b555fb422d1b6"
		logic_hash = "f48ed7f19ab29633600fde4bfea274bf36e7f60d700c9806b334d38a51d28b92"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8496ec66e276304108184db36add64936500f1f0dd74120e03b78c64ac7b5ba1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 54 24 38 48 89 5C 24 48 48 85 C9 75 62 48 85 D2 75 30 48 89 9C 24 C8 00 }

	condition:
		all of them
}