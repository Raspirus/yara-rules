
rule ELASTIC_Linux_Cryptominer_Roboto_1F1Cfe9A : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Roboto (Linux.Cryptominer.Roboto)"
		author = "Elastic Security"
		id = "1f1cfe9a-ab4a-423c-a62b-ead6901e2a86"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Roboto.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "497a6d426ff93d5cd18cea623074fb209d4f407a02ef8f382f089f1ed3f108c5"
		logic_hash = "2171284991b0019379c8d271013a35237c37bc2e13d807caed86f8fb9d2ba418"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8dd9f4a091713b8992abd97474f66fdc7d34b0124f06022ab82942f88f3b330c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 24 20 85 FF 74 0D 39 FE 73 13 83 FE 0F 77 0E 01 F6 EB F3 BF 01 00 }

	condition:
		all of them
}