
rule ELASTIC_Linux_Trojan_Mirai_564B8Eda : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "564b8eda-6f0e-45b8-bef6-d61b0f090a36"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L418-L436"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ff04921d7bf9ca01ae33a9fc0743dce9ca250e42a33547c5665b1c9a0b5260ee"
		logic_hash = "4bf11492f480911629623250146554f2456f3a527f5f80402ef74b22c1460462"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "63a9e43902e7db0b7a20498b5a860e36201bacc407e9e336faca0b7cfbc37819"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 83 FE 01 76 12 0F B7 07 83 EE 02 48 83 C7 02 48 01 C1 83 FE 01 }

	condition:
		all of them
}