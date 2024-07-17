
rule ELASTIC_Windows_Generic_Threat_4B0B73Ce : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "4b0b73ce-960d-40ce-ae85-5cf38d949f45"
		date = "2024-06-05"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L3505-L3523"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "236fc00cd7c75f70904239935ab90f51b03ff347798f56cec1bdd73a286b24c1"
		logic_hash = "d53923df612dd7fe0b1b2c94c1c5d747b08723df129089326ec27c5049769cef"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "11c544f9f3a51ffcd361d6558754a64a8a38f3ce9385038880ab58c99769db88"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 51 53 56 57 8B 7D 08 83 7F 18 00 C6 45 FF C9 74 54 ?? ?? ?? ?? ?? ?? 8D 9B 00 00 00 00 33 F6 83 7F 18 00 74 40 6A 0A FF D3 46 81 FE E8 03 00 00 7C ED 8B 07 8B 50 08 6A 01 8D 4D FF 51 }

	condition:
		all of them
}