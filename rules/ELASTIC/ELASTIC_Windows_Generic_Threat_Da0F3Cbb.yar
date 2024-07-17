
rule ELASTIC_Windows_Generic_Threat_Da0F3Cbb : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "da0f3cbb-e894-48a3-9169-b011e7ab278d"
		date = "2024-01-22"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1991-L2009"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b2c456d0051ffe1ca7e9de1e944692b10ed466eabb38242ea88e663a23157c58"
		logic_hash = "262d0bbb69adde8c4c8645813b048f3aaa2dbcc83996606e7ca21c3edea2b5d8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f50116e1f153d2a0e1e2dad879ba8bd6ac9855a563f6cbcbe6b6a06a96e86299"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 8B 45 0C 53 56 83 F8 FF 57 8B F1 74 03 89 46 10 8B 7D 08 33 DB 3B FB 75 17 FF 76 04 E8 C6 09 00 00 59 89 5E 04 89 5E 0C 89 5E 08 E9 D9 00 00 00 8B 4E 04 3B CB 75 23 8D 1C 3F 53 E8 7E }

	condition:
		all of them
}