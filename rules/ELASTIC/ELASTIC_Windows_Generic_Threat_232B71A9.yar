
rule ELASTIC_Windows_Generic_Threat_232B71A9 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "232b71a9-add2-492d-8b9a-ad2881826ecf"
		date = "2023-12-20"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L282-L300"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1e8b34da2d675af96b34041d4e493e34139fc8779f806dbcf62a6c9c4d9980fe"
		logic_hash = "c3bef1509c0d0172dbbc7e0e2b5c69e5ec47dc22365d98a914002b53b0f7d918"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "908e2a968e544dfb08a6667f78c92df656c7f2c5cf329dbba6cfdb5ea7b51a57"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 61 61 62 63 64 65 65 66 67 68 69 69 6A 6B 6C 6D 6E 6F 6F 70 71 72 73 74 75 75 76 77 78 79 7A 61 55 }

	condition:
		all of them
}