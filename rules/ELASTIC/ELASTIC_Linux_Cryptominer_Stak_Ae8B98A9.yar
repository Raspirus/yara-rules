rule ELASTIC_Linux_Cryptominer_Stak_Ae8B98A9 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Stak (Linux.Cryptominer.Stak)"
		author = "Elastic Security"
		id = "ae8b98a9-cc25-4606-a775-1129e0f08c3b"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Stak.yar#L21-L38"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "aade76488aa2f557de9082647153cca374a4819cd8e539ebba4bfef2334221b0"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0b5da501c97f53ecd79d708d898d4f5baae3c5fd80a4c39b891a952c0bcc86e5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { D1 73 5A 49 8B 06 48 8B 78 08 4C 8B 10 4C 8D 4F 18 4D 89 CB 49 }

	condition:
		all of them
}