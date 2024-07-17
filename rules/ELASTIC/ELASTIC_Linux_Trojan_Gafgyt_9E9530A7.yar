
rule ELASTIC_Linux_Trojan_Gafgyt_9E9530A7 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "9e9530a7-ad4d-4a44-b764-437b7621052f"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L178-L196"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "01da73e0d425b4d97c5ad75c49657f95618b394d09bd6be644eb968a3b894961"
		logic_hash = "6a5a80e58c86a80f8954e678a2cc26b258d7d7c50047a3e71f3580f1780e3454"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d6ad6512051e87c8c35dc168d82edd071b122d026dce21d39b9782b3d6a01e50"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F6 48 63 FF B8 36 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 }

	condition:
		all of them
}