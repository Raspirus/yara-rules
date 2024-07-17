rule ELASTIC_Windows_Generic_Threat_0350Ed31 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "0350ed31-ed07-4e9a-8488-3765c990f25c"
		date = "2024-01-07"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L753-L771"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "008f9352765d1b3360726363e3e179b527a566bc59acecea06bd16eb16b66c5d"
		logic_hash = "149dd26466f47b2e7f514bdcc9822470334490da2898840f35fe6b537ce104f6"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "aac41abf60a16c02c6250c0468c6f707f9771b48da9e78633de7141d09ca23c8"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 35 6A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 3F }

	condition:
		all of them
}