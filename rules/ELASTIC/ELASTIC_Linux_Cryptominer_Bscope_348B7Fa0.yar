rule ELASTIC_Linux_Cryptominer_Bscope_348B7Fa0 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Bscope (Linux.Cryptominer.Bscope)"
		author = "Elastic Security"
		id = "348b7fa0-e226-4350-8697-345ae39fa0f6"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Bscope.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a6fb80d77986e00a6b861585bd4e573a927e970fb0061bf5516f83400ad7c0db"
		logic_hash = "bc6a59dcc36676273c61fa71231fd8709884beebb7ab64b58f22551393b20c71"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "caae9d3938f9269f8bc30e4837021513ca6e4e2edd1117d235b0d25474df5357"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 04 8B 00 03 45 C0 89 02 8B 45 08 8D 50 08 8B 45 08 83 C0 08 }

	condition:
		all of them
}