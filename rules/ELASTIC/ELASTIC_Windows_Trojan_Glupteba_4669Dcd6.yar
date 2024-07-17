rule ELASTIC_Windows_Trojan_Glupteba_4669Dcd6 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Glupteba (Windows.Trojan.Glupteba)"
		author = "Elastic Security"
		id = "4669dcd6-8e04-416d-91c0-f45816430869"
		date = "2021-08-08"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Glupteba.yar#L26-L44"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1b55042e06f218546db5ddc52d140be4303153d592dcfc1ce90e6077c05e77f7"
		logic_hash = "64b2099f40f94b17bc5860b41773c41322420500696d320399ff1c016cb56e15"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5b598640f42a99b00d481031f5fcf143ffcc32ef002eac095a14edb18d5b02c9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 40 C3 8B 44 24 48 8B 4C 24 44 89 81 AC 00 00 00 8B 44 24 4C 89 81 B0 00 }

	condition:
		all of them
}