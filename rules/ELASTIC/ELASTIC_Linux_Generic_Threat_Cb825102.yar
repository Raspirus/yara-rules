rule ELASTIC_Linux_Generic_Threat_Cb825102 : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "cb825102-0b03-4885-9f73-44dd0cf2d45c"
		date = "2024-02-21"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L676-L694"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4e24b72b24026e3dfbd65ddab9194bd03d09446f9ff0b3bcec76efbb5c096584"
		logic_hash = "ac48f32ec82aac6df0697729d14aaee65fba82d91173332cd13c6ccccd63b1be"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "e23ac81c245de350514c54f91e8171c8c4274d76c1679500d6d2b105f473bdfc"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 5B 2B 5D 20 72 65 73 6F 6C 76 69 6E 67 20 72 65 71 75 69 72 65 64 20 73 79 6D 62 6F 6C 73 2E 2E 2E }

	condition:
		all of them
}