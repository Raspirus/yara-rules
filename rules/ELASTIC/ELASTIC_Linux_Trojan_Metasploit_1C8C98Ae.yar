rule ELASTIC_Linux_Trojan_Metasploit_1C8C98Ae : FILE MEMORY
{
	meta:
		description = "Detects x86 msfvenom add user payloads"
		author = "Elastic Security"
		id = "1c8c98ae-46c8-45fe-ab42-7b053f0357ed"
		date = "2024-05-07"
		modified = "2024-05-21"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Metasploit.yar#L231-L251"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1a2c40531584ed485f3ff532f4269241a76ff171956d03e4f0d3f9c950f186d4"
		logic_hash = "fc32aa29f58478f0b7f4f5be61aadec65842c05b7d8ded840530503eae28b8eb"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a3b592cc6d9b00f76a1084c7c124cc199149ada5b8dc206cff3133718f045c9d"
		threat_name = "Linux.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$str1 = { 31 C9 89 CB 6A 46 58 CD 80 6A 05 58 31 C9 51 68 73 73 77 64 68 2F 2F 70 61 68 2F 65 74 63 89 E3 41 B5 04 CD 80 93 }
		$str2 = { 59 8B 51 FC 6A 04 58 CD 80 6A 01 58 CD 80 }

	condition:
		all of them
}