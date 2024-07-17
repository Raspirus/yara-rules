rule ELASTIC_Linux_Cryptominer_Generic_0D6005A1 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "0d6005a1-a481-4679-a214-f1e3ef8bf1d0"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L301-L319"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "230d46b39b036552e8ca6525a0d2f7faadbf4246cdb5e0ac9a8569584ef295d4"
		logic_hash = "c3fd32e7582f0900b94fe3ba6b6bcdf238f78e2e343d70d5b0196a968a41cf26"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "435040ec452d337c60435b07622d3a8af8e3b7e8eb6ec2791da6aae504cc2266"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 79 73 00 6E 6F 5F 6D 6C 63 6B 00 77 61 72 6E 00 6E 65 76 65 }

	condition:
		all of them
}