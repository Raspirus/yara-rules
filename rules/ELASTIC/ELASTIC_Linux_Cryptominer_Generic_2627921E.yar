rule ELASTIC_Linux_Cryptominer_Generic_2627921E : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "2627921e-6c0d-4515-a09a-b2c99a59598d"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L701-L719"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "350a8ceabd8495e66cc58885f1ab38f602c66c162c05e4b6ae0e2a7977ec2cdf"
		logic_hash = "edb2864719d62ab212bde1adf02dd17c8edc8ce4ae273b959e58a3eaf751fd7c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2551ece438a09700c825faa63caa3e21ced94c85bdaa5b1b0dd63603d4fa9bb6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 0F 6F D0 66 44 0F 6F C1 66 0F 69 E2 66 44 0F 61 D2 66 44 0F }

	condition:
		all of them
}