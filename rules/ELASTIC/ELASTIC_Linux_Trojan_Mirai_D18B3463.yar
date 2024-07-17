
rule ELASTIC_Linux_Trojan_Mirai_D18B3463 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "d18b3463-1b5e-49e1-9ae8-1d63a10a1ccc"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1047-L1065"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "cd86534d709877ec737ceb016b2a5889d2e3562ffa45a278bc615838c2e9ebc3"
		logic_hash = "f906c6f9baae6d6fa3f42e84607549bae44ed9ca847fd916d04f2671eef1caa1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4b3d3bb65db2cdb768d91c50928081780f206208e952c74f191d8bc481ce19c6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { DF 77 95 8D 42 FA 3C 01 76 8E 80 FA 0B 74 89 80 FA 15 74 84 80 }

	condition:
		all of them
}