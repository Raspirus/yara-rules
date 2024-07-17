rule ELASTIC_Linux_Generic_Threat_1E047045 : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "1e047045-e08b-4ecb-8892-90a1ab94f8b1"
		date = "2024-02-21"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L862-L880"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2c49772d89bcc4ad4ed0cc130f91ed0ce1e625262762a4e9279058f36f4f5841"
		logic_hash = "0d28df53e030664e7225f1170888b51e94e64833537c5add3e10cfdb4f029a3a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "aa99b16f175649c251cb299537baf8bded37d85af8b2539b4aba4ffd634b3f66"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 18 48 89 FB 48 89 F5 64 48 8B 04 25 28 00 00 00 48 89 44 24 08 31 C0 48 8B 47 08 48 89 C2 48 C1 EA 18 88 14 24 48 89 C2 48 C1 EA 10 88 54 24 01 48 89 C2 48 C1 EA 08 88 54 24 02 88 44 }

	condition:
		all of them
}