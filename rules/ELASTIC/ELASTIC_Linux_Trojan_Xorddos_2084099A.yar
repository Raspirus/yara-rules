rule ELASTIC_Linux_Trojan_Xorddos_2084099A : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Xorddos (Linux.Trojan.Xorddos)"
		author = "Elastic Security"
		id = "2084099a-1df6-4481-9d13-3a5bd6a53817"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Xorddos.yar#L118-L135"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "6674be1438ec290550c9586afda335755279a4aedadde455ffc0b41d1a0e634d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "dfb813a5713f0e7bdb5afd500f1e84c6f042c8b1a1d27dd6511dca7f2107c13b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 8B 45 FC 8B 50 18 8B 45 08 89 50 18 8B 45 FC 8B 40 08 85 C0 }

	condition:
		all of them
}