
rule ELASTIC_Windows_Trojan_Donutloader_F40E3759 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Donutloader (Windows.Trojan.Donutloader)"
		author = "Elastic Security"
		id = "f40e3759-2531-4e21-946a-fb55104814c0"
		date = "2021-09-15"
		modified = "2022-01-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Donutloader.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "541a4ca1da41f7cf54dff3fee917b219fadb60fd93a89b93b5efa3c1a57af81d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a6b9ccd69d871de081759feca580b034e3c5cec788dd5b3d3db033a5499735b5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$x64 = { 06 B8 03 40 00 80 C3 4C 8B 49 10 49 8B 81 30 08 00 00 }
		$x86 = { 04 75 EE 89 31 F0 FF 46 04 33 C0 EB 08 83 21 00 B8 02 }

	condition:
		any of them
}