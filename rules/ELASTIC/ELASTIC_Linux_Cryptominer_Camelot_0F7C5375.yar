rule ELASTIC_Linux_Cryptominer_Camelot_0F7C5375 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Camelot (Linux.Cryptominer.Camelot)"
		author = "Elastic Security"
		id = "0f7c5375-99dc-4204-833a-9128798ed2e9"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Camelot.yar#L218-L236"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e75be5377ad65abdc69e6c7f9fe17429a98188a217d0ca3a6f40e75c4f0c07e8"
		logic_hash = "05f4b16a7e4c7ffbc6b8a2f60050a4ac1d05d9efbe948e2da689055f6383cf82"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "53bb31c6ba477ed86e55ce31844055c26d7ab7392d78158d3f236d621181ca10"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F8 7F 48 89 85 C0 00 00 00 77 08 48 83 85 C8 00 00 00 01 31 F6 48 }

	condition:
		all of them
}