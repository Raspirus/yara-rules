rule ELASTIC_Windows_Generic_Threat_D51Dd31B : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "d51dd31b-1735-4fd7-9906-b07406a9d20c"
		date = "2024-01-24"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2131-L2150"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2a61c0305d82b6b4180c3d817c28286ab8ee56de44e171522bd07a60a1d8492d"
		logic_hash = "85fc7aa81489b304c348ead2d7042bb5518ff4579b1d3e837290032c4b144e47"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "f313354a52ba8058c36aea696fde5548c7eb9211cac3b6caa511671445efe2a7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 7E 7D 7C 7B 7A 79 78 78 76 77 74 73 72 }
		$a2 = { 6D 6C 6B 6A 69 68 67 66 65 64 63 62 61 60 60 5E 66 60 5B 5A }

	condition:
		all of them
}