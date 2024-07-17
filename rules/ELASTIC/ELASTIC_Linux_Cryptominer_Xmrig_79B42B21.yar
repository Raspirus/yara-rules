rule ELASTIC_Linux_Cryptominer_Xmrig_79B42B21 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Xmrig (Linux.Cryptominer.Xmrig)"
		author = "Elastic Security"
		id = "79b42b21-1408-4837-8f1f-6de30d7f5777"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Xmrig.yar#L80-L97"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "db42871193960ea4c2cbe5f5040cbc1097d57d9e4dc291bcc77ed72b588311ab"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4cd0481edd1263accdac3ff941df4e31ef748bded0fba5fe55a9cffa8a37b372"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { FC 00 79 0A 8B 45 B8 83 E0 04 85 C0 75 38 8B 45 EC 83 C0 01 }

	condition:
		all of them
}