
rule ELASTIC_Linux_Generic_Threat_A658B75F : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "a658b75f-3520-4ec6-b3d4-674bc22380b3"
		date = "2024-01-17"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "df430ab9f5084a3e62a6c97c6c6279f2461618f038832305057c51b441c648d9"
		logic_hash = "1ef7267438b8d15ed770f0784a7d428cbc2680144b0ef179337875d5b4038d08"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "112be9d42b300ce4c2e0d50c9e853d3bdab5d030a12d87aa9bae9affc67cd6cd"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 6D 61 69 6E 2E 45 6E 63 72 79 70 74 46 69 6C 65 52 65 61 64 57 72 69 74 65 }
		$a2 = { 6D 61 69 6E 2E 53 63 61 6E 57 61 6C 6B 65 72 }

	condition:
		all of them
}