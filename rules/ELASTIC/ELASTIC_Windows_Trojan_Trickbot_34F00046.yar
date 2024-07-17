rule ELASTIC_Windows_Trojan_Trickbot_34F00046 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Trickbot (Windows.Trojan.Trickbot)"
		author = "Elastic Security"
		id = "34f00046-8938-4103-91ec-4a745a627d4a"
		date = "2021-03-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L231-L248"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "f9d646645d6726e3aac5cc3eaea9edf1c89c7e743aff7cfa73998a72f3446711"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5c6f11e2a040ae32336f4b4c4717e0f10c73359899302b77e1803f3a609309c0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 30 FF FF FF 03 08 8B 95 30 FF FF FF 2B D1 89 95 30 FF FF FF }

	condition:
		all of them
}