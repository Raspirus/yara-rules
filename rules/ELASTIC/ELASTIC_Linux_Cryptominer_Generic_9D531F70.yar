rule ELASTIC_Linux_Cryptominer_Generic_9D531F70 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "9d531f70-c42f-4e1a-956a-f9ac43751e73"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L101-L119"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "36f2ce4e34faf42741f0a15f62e8b3477d69193bf289818e22d0e3ee3e906eb0"
		logic_hash = "87d3cb7049975d52f2a6d6aa10e6b6d0d008d166ca5f9889ad1413a573d8b58e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2c6019f7bc2fc47d7002e0ba6e35513950260b558f1fdc732d3556dabbaaa93d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 49 10 58 00 10 D4 34 80 08 30 01 20 02 00 B1 00 83 49 23 16 54 }

	condition:
		all of them
}