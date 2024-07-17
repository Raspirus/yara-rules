
rule ELASTIC_Windows_Generic_Threat_742E8A70 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "742e8a70-c150-4903-a551-9123587dd473"
		date = "2023-12-18"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L242-L260"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "94f7678be47651aa457256375f3e4d362ae681a9524388c97dc9ed34ba881090"
		logic_hash = "2925eb8da80ef791b5cf7800a9bf9462203ab6aa743bc69f4fd2343e97eaab7c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "733b3563275da0a1b4781b9c0aa07e6e968133ae099eddef9cad3793334b9aa5"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC E8 96 FF FF FF E8 85 0D 00 00 83 7D 08 00 A3 A4 E9 43 00 74 05 E8 0C 0D 00 00 DB E2 5D C3 8B FF 55 8B EC 83 3D B0 E9 43 00 02 74 05 E8 BA 12 00 00 FF 75 08 E8 07 11 00 00 68 FF 00 00 }

	condition:
		all of them
}