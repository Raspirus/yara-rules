
rule ELASTIC_Linux_Cryptominer_Generic_050Ac14C : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "050ac14c-9aef-4212-97fd-e2a21c2f62e2"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L481-L499"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "36f2ce4e34faf42741f0a15f62e8b3477d69193bf289818e22d0e3ee3e906eb0"
		logic_hash = "c34b0ff3ce867a76ef57fad7642de7916fa7baebf1a2a8d514f7b74be7231fd4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6f0a5a5d3cece7ae8db47ef5e1bbbea02b886e865f23b0061c2d346feb351663"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 47 08 49 3B 47 10 74 3C 48 85 C0 74 16 48 8B 13 48 89 10 48 8B }

	condition:
		all of them
}