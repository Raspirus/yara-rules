rule ELASTIC_Linux_Trojan_Metasploit_Da378432 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Metasploit (Linux.Trojan.Metasploit)"
		author = "Elastic Security"
		id = "da378432-d549-4ba8-9e33-a0d0656fc032"
		date = "2024-05-03"
		modified = "2024-05-21"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Metasploit.yar#L73-L93"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "277499da700e0dbe27269c7cfb1fc385313c4483912a9a3f0c15adba33ecd0bf"
		logic_hash = "cd9df6dff23986d61176e4d3440516b0590abdeebef0e456d1f4924724556fe9"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "db6e226c18211d845c3495bb39472646e64842d4e4dd02d9aad29178fd22ea95"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$str1 = { 6A 29 58 99 6A 02 5F 6A 01 5E 0F 05 48 97 }
		$str2 = { 6A 10 5A 6A ?? 58 0F }
		$str3 = { 6A 03 5E 48 FF CE 6A 21 58 0F 05 75 F6 6A 3B 58 99 48 BB 2F 62 69 6E 2F 73 68 00 53 48 89 E7 52 57 48 89 E6 0F 05 }

	condition:
		all of them
}