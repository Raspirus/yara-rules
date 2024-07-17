rule ELASTIC_Windows_Generic_Threat_Fcab7E76 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "fcab7e76-5edd-4485-9983-bcc5e9cb0a08"
		date = "2024-01-12"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1097-L1115"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "67d7e016e401bd5d435eecaa9e8ead341aed2f373a1179069f53b64bda3f1f56"
		logic_hash = "90f50d1227b8e462eaa393690dc2b25601444bf80f2108445a0413bff6bedae8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8a01a3a398cfaa00c1b194b2abc5a0c79d21010abf27dffe5eb8fdc602db7ad1"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 28 FA 00 2B CD 65 50 7C FF CF 34 00 80 41 BF 1E 12 1A F9 20 0F 56 EE 9F BA C0 22 7E 97 FC CB 03 C7 67 9A AE 8A 60 C0 B3 6C 0D 00 2B 2C 78 83 B5 88 03 17 3A 51 4A 1F 30 D2 C0 53 DC 09 7A BF 2D }

	condition:
		all of them
}