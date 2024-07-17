
rule ELASTIC_Windows_Generic_Threat_F45B3F09 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "f45b3f09-4203-41f7-870e-d8ef5126c391"
		date = "2024-03-05"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L3164-L3182"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "577f1dbd76030c7e44ed28c748551691d446e268189af94e1fa1545f06395178"
		logic_hash = "9b01ad1271cc5052a793e5a885aa7289cbaea4a928f60d64194477c3036496ed"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "dfa72e0780e895ab5aa2369a425c64144e9bd435e55d8a0fefbe08121ae31df5"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 28 33 ED 44 8B ED 48 89 6C 24 78 44 8B FD 48 89 AC 24 88 00 00 00 44 8B F5 44 8B E5 E8 43 04 00 00 48 8B F8 8D 75 01 ?? ?? ?? ?? ?? 66 39 07 75 1A 48 63 47 3C 48 8D 48 C0 }

	condition:
		all of them
}