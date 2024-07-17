rule ELASTIC_Linux_Generic_Threat_Ace836F1 : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "ace836f1-74f0-4031-903b-ec5b95a40d46"
		date = "2024-05-21"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L1132-L1150"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "116aaba80e2f303206d0ba84c8c58a4e3e34b70a8ca2717fa9cf1aa414d5ffcc"
		logic_hash = "c80af9d6f3e4d92cfa53429abbda944069d335fc89421a89e04089d236f5dddf"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "907b40e66d5da2faf142917304406d0a8abc7356d73b2a6a6789be22b4daf4ab"
		severity = 50
		arch_context = "x86, arm64"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 4E 54 4C 4D 53 53 50 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 73 25 73 }

	condition:
		all of them
}