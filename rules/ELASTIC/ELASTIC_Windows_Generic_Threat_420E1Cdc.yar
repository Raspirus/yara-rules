rule ELASTIC_Windows_Generic_Threat_420E1Cdc : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "420e1cdc-2d47-437a-986d-ff22d2fac978"
		date = "2024-03-04"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2902-L2920"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b20254e03f7f1e79fec51d614ee0cfe0cb87432f3a53cf98cf8c047c13e2d774"
		logic_hash = "6bd8a7bd4392e04d64f2e0b93d80978f59f9af634a0c971ca61cb9cb593743e0"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "33f35c5c73656fc5987c39fabefa1225fef1734f4217518a1b6e7a78669c90c5"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 51 56 8B 75 08 85 F6 74 5A ?? ?? ?? ?? ?? 83 F8 03 75 16 56 E8 ED 01 00 00 59 85 C0 56 74 36 50 E8 0C 02 00 00 59 59 EB 3A 83 F8 02 75 26 8D 45 08 50 8D 45 FC 50 56 E8 25 0F 00 00 }

	condition:
		all of them
}