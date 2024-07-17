
rule ELASTIC_Windows_Trojan_Cobaltstrike_8D5963A2 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Cobaltstrike (Windows.Trojan.CobaltStrike)"
		author = "Elastic Security"
		id = "8d5963a2-54a9-4705-9f34-0d5f8e6345a2"
		date = "2022-08-10"
		modified = "2022-09-29"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_CobaltStrike.yar#L971-L989"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9fe43996a5c4e99aff6e2a1be743fedec35e96d1e6670579beb4f7e7ad591af9"
		logic_hash = "f4f8fba807256bd885ccf4946eec8c2fb76eb04f86ed76d015178fe512a3c091"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "228cd65380cf4b04f9fd78e8c30c3352f649ce726202e2dac9f1a96211925e1c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 D8 48 81 EC 28 01 00 00 45 33 F6 48 8B D9 48 }

	condition:
		all of them
}