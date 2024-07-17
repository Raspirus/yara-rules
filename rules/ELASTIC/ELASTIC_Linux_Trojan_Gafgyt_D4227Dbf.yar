rule ELASTIC_Linux_Trojan_Gafgyt_D4227Dbf : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "d4227dbf-6ab4-4637-a6ba-0e604acaafb4"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L494-L512"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "01da73e0d425b4d97c5ad75c49657f95618b394d09bd6be644eb968a3b894961"
		logic_hash = "7953b8d08834315a6ca2c0c8ac1ec7b74a6ffcb71cec4fc053c24e1b59232c0c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "58c4b1d4d167876b64cfa10f609911a80284180e4db093917fea16fae8ccd4e3"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { FF 48 81 EC D0 00 00 00 48 8D 84 24 E0 00 00 00 48 89 54 24 30 C7 04 24 18 00 }

	condition:
		all of them
}