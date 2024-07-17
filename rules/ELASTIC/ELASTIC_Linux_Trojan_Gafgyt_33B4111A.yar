
rule ELASTIC_Linux_Trojan_Gafgyt_33B4111A : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "33b4111a-e59e-48db-9d74-34ca44fcd9f5"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L971-L989"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "01da73e0d425b4d97c5ad75c49657f95618b394d09bd6be644eb968a3b894961"
		logic_hash = "a08c0f7be26e2e9abfaa392712895bb3ce1d12583da4060ebe41e1a9c1491b7c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9c3b63b9a0f54006bae12abcefdb518904a85f78be573f0780f0a265b12d2d6e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C1 83 E1 0F 74 1A B8 10 00 00 00 48 29 C8 48 8D 0C 02 48 89 DA 48 }

	condition:
		all of them
}