rule ELASTIC_Linux_Generic_Threat_66D00A84 : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "66d00a84-c148-4a82-8da5-955787c103a4"
		date = "2024-02-21"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L903-L921"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "464e144bcbb54fc34262b4d81143f4e69e350fb526c803ebea1fdcfc8e57bf33"
		logic_hash = "a1d60619d72b3309bfaaf8b4085dd5ed90142ff3e9ebfe80fcd7beba5f14a62e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1b6c635dc149780691f292014f3dbc20755d26935b7ae0b3d8f250c10668e28a"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 48 81 EC 10 04 00 00 4C 89 E7 49 8D 8C 24 FF 03 00 00 49 89 E0 48 89 E0 8A 17 84 D2 74 14 80 7F 01 00 88 10 74 05 48 FF C0 EB 07 88 58 01 48 83 C0 02 48 FF C7 48 39 F9 75 DE 4C 39 C0 74 06 C6 }

	condition:
		all of them
}