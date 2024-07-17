rule ELASTIC_Windows_Generic_Threat_7A09E97D : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "7a09e97d-ccab-48d7-80d3-d76253a4d7e2"
		date = "2024-01-21"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1851-L1869"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c0c1e333e60547a90ec9d9dac3fc6698b088769bc0f5ec25883b2c4d1fd680a9"
		logic_hash = "b65b2d12901953c137687a7b466c78e0537a2830c37a4cb13dd0eda457bba937"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3302bbee32c9968d3131277f4256c5673bec6cc64c1d820a32e66a7313387415"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 28 00 00 06 2A 3A FE 09 00 00 FE 09 01 00 6F 8D 00 00 0A 2A 00 4A FE 09 00 00 FE 09 01 00 FE 09 02 00 6F 8E 00 00 0A 2A 00 1E 00 28 43 00 00 06 2A 5A FE 09 00 00 FE 09 01 00 FE 09 02 00 FE 09 }

	condition:
		all of them
}