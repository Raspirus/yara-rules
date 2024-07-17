rule ELASTIC_Linux_Cryptominer_Xmrig_Bffa106B : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Xmrig (Linux.Cryptominer.Xmrig)"
		author = "Elastic Security"
		id = "bffa106b-0a9a-4433-b9ac-ae41a020e7e0"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Xmrig.yar#L139-L156"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "d7214ad9c4291205b50567d142d99b8a19a9cfa69d3cd0a644774c3a1adb6b49"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "665b5684c55c88e55bcdb8761305d6428c6a8e810043bf9df0ba567faea4c435"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 54 24 9C 44 0F B6 94 24 BC 00 00 00 89 5C 24 A0 46 8B 0C 8A 66 0F 6E 5C }

	condition:
		all of them
}