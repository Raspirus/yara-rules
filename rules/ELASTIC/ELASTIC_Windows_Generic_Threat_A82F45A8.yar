rule ELASTIC_Windows_Generic_Threat_A82F45A8 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "a82f45a8-8e47-4966-9d48-9af61a21ac42"
		date = "2024-01-29"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2172-L2190"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ad07428104d3aa7abec2fd86562eaa8600d3e4b0f8d78ba1446f340d10008b53"
		logic_hash = "70ebab6b03af38ef8c81664cf49ab07066a9672666599d99c91291a9d2e3af0b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e3a1faabc15e2767eb065f4e2a7c6f75590cba1368db1aab1af972a5aeca4031"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 51 89 4D FC 8B 4D 08 51 8B 4D FC 83 C0 04 E8 66 7D F6 FF 59 5D C2 08 00 90 55 8B EC 51 89 4D FC 8B 4D 08 51 41 51 8B 4D FC E8 CF FF FF FF 59 5D C2 04 00 8B C0 55 8B EC 83 C4 F8 53 56 }

	condition:
		all of them
}