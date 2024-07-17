
rule ELASTIC_Linux_Trojan_Metasploit_Dd5Fd075 : FILE MEMORY
{
	meta:
		description = "Detects x86 msfvenom TCP bind shell payloads"
		author = "Elastic Security"
		id = "dd5fd075-bd52-47a9-b737-e55ab10a071d"
		date = "2024-05-07"
		modified = "2024-05-21"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Metasploit.yar#L422-L443"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b47132a92b66c32c88f39fe36d0287c6b864043273939116225235d4c5b4043a"
		logic_hash = "f5101d5ddb1a84127e755677da70d9154849c546ac6ef0e7ef2639c82911eb92"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "df2a4f90ec3227555671136c18931118fc9df32340d87aeb3f3fa7fdf2ba6179"
		threat_name = "Linux.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$str1 = { 31 DB F7 E3 53 43 53 6A 02 89 E1 B0 66 CD 80 5B 5E 52 }
		$str2 = { 6A 10 51 50 89 E1 6A 66 58 CD 80 89 41 04 B3 04 B0 66 CD 80 43 B0 66 CD 80 93 59 }
		$str3 = { 6A 3F 58 CD 80 49 79 F8 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 50 53 89 E1 B0 0B CD 80 }

	condition:
		all of them
}