
rule ELASTIC_Windows_Generic_Threat_5C18A7F9 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "5c18a7f9-01af-468b-9a63-cfecbeb739d7"
		date = "2024-01-21"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1789-L1807"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "fd272678098eae8f5ec8428cf25d2f1d8b65566c59e363d42c7ce9ffab90faaa"
		logic_hash = "05cea396567ed3e23907dec4e6e3a6629cd1044d9123cde0575a04b73bae6c20"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "68c9114ac342d527cf6f0cea96b63dfeb8e5d80060572fad2bbc7d287c752d4a"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 5D E9 CD 1A 00 00 8B FF 55 8B EC 51 FF 75 08 C7 45 FC 00 00 00 00 8B 45 FC E8 03 1B 00 00 59 C9 C3 8B FF 55 8B EC 51 56 57 E8 6B 18 00 00 8B F0 85 F6 74 1C 8B 16 8B CA 8D 82 90 00 00 }

	condition:
		all of them
}