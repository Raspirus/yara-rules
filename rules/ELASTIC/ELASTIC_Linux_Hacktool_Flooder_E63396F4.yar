rule ELASTIC_Linux_Hacktool_Flooder_E63396F4 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "e63396f4-a297-4d99-b341-34cb22498078"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L480-L498"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "913e6d2538bd7eed3a8f3d958cf445fe11c5c299a70e5385e0df6a9b2f638323"
		logic_hash = "d3f7c62a7411caf86ee574a686b4b1972066602f89d39ae9e49ba66d9917c7c9"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "269285d03ea1a3b41ff134ab2cf5e22502626c72401b83add6c1e165f4dd83f8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 02 83 45 FC 01 81 7D FC FF 0F 00 00 7E ?? 90 }

	condition:
		all of them
}