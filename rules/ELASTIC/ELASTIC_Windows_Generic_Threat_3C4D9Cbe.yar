rule ELASTIC_Windows_Generic_Threat_3C4D9Cbe : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "3c4d9cbe-700f-4f3e-8e66-d931d5c90d3e"
		date = "2024-01-31"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2396-L2414"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "21d01bd53f43aa54f22786d7776c7bc90320ec6f7a6501b168790be46ff69632"
		logic_hash = "b32f9a3b86c60d4d69c59250ac59e93aee70ede890b059b13be999adbe043d2c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "15be51c438b7b2a167e61e35821445404a38c2f8c3e037061a1eba4bf0ded2b5"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 53 56 57 8B 55 08 8B DA 8B 7A 3C 03 FA 66 81 3F 50 45 75 54 03 5F 78 8B 4B 18 8B 73 20 8B 7B 24 03 F2 03 FA FC 55 8B 6D 0C AD 03 C2 96 87 FD 51 33 C9 80 C1 0F F3 A6 72 0C 96 59 87 FD }

	condition:
		all of them
}