
rule ELASTIC_Linux_Cryptominer_Generic_9C8F3B1A : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "9c8f3b1a-0273-4164-ba48-b0bc090adf9e"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L361-L379"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "74d8344139c5deea854d8f82970e06fc6a51a6bf845e763de603bde7b8aa80ac"
		logic_hash = "f7ab9990b417c1c81903dcb7adaae910d20ea7fce6689d4846dd6002bea3e721"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a35efe6bad4e0906032ab2fd7c776758e71caed8be402948f39682cf1f858005"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 6F 67 31 70 00 6C 6F 67 32 66 00 6C 6C 72 6F 75 6E 64 00 73 71 }

	condition:
		all of them
}