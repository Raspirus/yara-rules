rule ELASTIC_Windows_Trojan_Trickbot_515504E2 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Trickbot (Windows.Trojan.Trickbot)"
		author = "Elastic Security"
		id = "515504e2-6b7f-4398-b89b-3af2b46c78a7"
		date = "2021-03-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L155-L172"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "5410068e09de4a1283f98f6364ddf243373e228ba060b00699db6323f1167684"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8eb741e1b3bd760e2cf511ad6609ac6f1f510958a05fb093eae26462f16ee1d0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 6A 00 6A 00 8D 4D E0 51 FF D6 85 C0 74 29 83 F8 FF 74 0C 8D }

	condition:
		all of them
}