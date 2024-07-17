rule ELASTIC_Linux_Trojan_Xorddos_2522D611 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Xorddos (Linux.Trojan.Xorddos)"
		author = "Elastic Security"
		id = "2522d611-4ce3-4583-87d6-e5631b62d562"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Xorddos.yar#L277-L295"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0c2be53e298c285db8b028f563e97bf1cdced0c4564a34e740289b340db2aac1"
		logic_hash = "59f2552809bc48e16719cb9b4d2a7b99999307803fce031ca39eb24e14b88908"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "985885a6b5f01e8816027f92148d2496a5535f3c15de151f05f69ec273291506"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 24 04 57 8B 7C 24 02 5F 87 44 24 00 50 8B 44 24 04 8D 40 42 87 44 }

	condition:
		all of them
}