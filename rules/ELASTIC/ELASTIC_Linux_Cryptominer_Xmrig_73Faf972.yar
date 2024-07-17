
rule ELASTIC_Linux_Cryptominer_Xmrig_73Faf972 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Xmrig (Linux.Cryptominer.Xmrig)"
		author = "Elastic Security"
		id = "73faf972-43e4-448d-bdfd-cda9be15fce6"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Xmrig.yar#L158-L176"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "00e29303b66cb39a8bc23fe91379c087376ea26baa21f6b7f7817289ba89f655"
		logic_hash = "a6a9d304d215302bf399c90ed0dd77a681796254c51a2a20e4a316dba43b387f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f31c2658acd6d13ae000426d3845bcec7a8a587bbaed75173baa84b2871b0b42"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 6F C4 83 E0 01 83 E1 06 09 C1 44 89 E8 01 C9 D3 }

	condition:
		all of them
}