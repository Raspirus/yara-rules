rule ELASTIC_Linux_Trojan_Metasploit_Ccc99Be1 : FILE MEMORY
{
	meta:
		description = "Detects x64 msfvenom pingback bind shell payloads"
		author = "Elastic Security"
		id = "ccc99be1-6ea9-4090-acba-3bbe82b127c1"
		date = "2024-05-07"
		modified = "2024-05-21"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Metasploit.yar#L305-L327"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0e9f52d7aa6bff33bfbdba6513d402db3913d4036a5e1c1c83f4ccd5cc8107c8"
		logic_hash = "96af2123251587ece32e424202ff61cfa70faf2916cacddf5fcd9d81bf483032"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "88e30402974b853e5f83a3033129d99e7dd1f6b31b5855b1602ef2659a0f7f56"
		threat_name = "Linux.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$str1 = { 56 50 6A 29 58 99 6A 02 5F 6A 01 5E 0F 05 48 85 C0 }
		$str2 = { 51 48 89 E6 54 5E 6A 31 58 6A 10 5A 0F 05 6A 32 58 6A 01 5E 0F 05 }
		$str3 = { 6A 2B 58 99 52 52 54 5E 6A 1C 48 8D 14 24 0F 05 48 97 }
		$str4 = { 5E 48 31 C0 48 FF C0 0F 05 6A 3C 58 6A 01 5F 0F 05 }

	condition:
		all of them
}