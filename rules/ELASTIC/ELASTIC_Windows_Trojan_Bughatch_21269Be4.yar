
rule ELASTIC_Windows_Trojan_Bughatch_21269Be4 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Bughatch (Windows.Trojan.Bughatch)"
		author = "Elastic Security"
		id = "21269be4-cff1-42b9-be6b-f6a6bde40bff"
		date = "2022-05-09"
		modified = "2022-06-09"
		reference = "https://www.elastic.co/security-labs/bughatch-malware-analysis"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Bughatch.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b495456a2239f3ba48e43ef295d6c00066473d6a7991051e1705a48746e8051f"
		logic_hash = "a8a2cae51a31e48ffe729df61ec96e3257f9c997ad5234075f85ed55de96f11d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1ff55288554133690d96161c05a047ffba47778ff27d32ff656b3a194d6c26e0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 8B 45 ?? 33 D2 B9 A7 00 00 00 F7 F1 85 D2 75 ?? B8 01 00 00 00 EB 33 C0 }
		$a2 = { 8B 45 ?? 0F B7 48 04 81 F9 64 86 00 00 75 3B 8B 55 ?? 0F B7 42 16 25 00 20 00 00 ?? ?? B8 06 00 00 00 EB ?? }
		$b1 = { 69 4D 10 FD 43 03 00 81 C1 C3 9E 26 00 89 4D 10 8B 55 FC 8B 45 F8 0F B7 0C 50 8B 55 10 C1 EA 10 81 E2 FF FF 00 00 33 CA 8B 45 FC 8B 55 F8 66 89 0C 42 }

	condition:
		any of them
}