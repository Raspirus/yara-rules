
rule ELASTIC_Linux_Trojan_Azeela_Aad9D6Cc : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Azeela (Linux.Trojan.Azeela)"
		author = "Elastic Security"
		id = "aad9d6cc-32ff-431a-9914-01c7adc80877"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Azeela.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6c476a7457ae07eca3d3d19eda6bb6b6b3fa61fa72722958b5a77caff899aaa6"
		logic_hash = "efc8b5de42a2ee2104dc8e8c25b313f6ced2fb291ba27dc8276822960dd7eb74"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3b7c73a378157350344d52acd6c210d5924cf55081b386d0d60345e4c44c5921"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C0 74 07 B8 01 00 00 00 EB 31 48 8B 45 F8 0F B6 00 3C FF 74 21 48 83 45 }

	condition:
		all of them
}