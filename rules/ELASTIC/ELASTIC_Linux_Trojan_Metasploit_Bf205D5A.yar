
rule ELASTIC_Linux_Trojan_Metasploit_Bf205D5A : FILE MEMORY
{
	meta:
		description = "Detects x86 msfvenom bind IPv6 TCP shell payloads "
		author = "Elastic Security"
		id = "bf205d5a-2bba-497a-8d40-58422e91fe45"
		date = "2024-05-07"
		modified = "2024-05-21"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Metasploit.yar#L373-L397"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2162a89f70edd7a7f93f8972c6a13782fb466cdada41f255f0511730ec20d037"
		logic_hash = "9f4c84fadc3d7555c80efc9c9c5dcb01d4ea65d2ff191aa63ae8316f763ded3f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "91ac22c6302de26717f0666c59fa3765144df2d22d0c3a311a106bc1d9d2ae70"
		threat_name = "Linux.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$str1 = { 6A 7D 58 99 B2 07 B9 00 10 00 00 89 E3 66 81 E3 00 F0 CD 80 31 DB F7 E3 53 43 53 6A ?? 89 E1 B0 66 CD 80 }
		$str2 = { 51 6A 04 54 6A 02 6A 01 50 }
		$str3 = { 6A 0E 5B 6A 66 58 CD 80 89 F8 83 C4 14 59 5B 5E }
		$str4 = { CD 80 93 B6 0C B0 03 CD 80 87 DF 5B B0 06 CD 80 }
		$ipv6 = { 6A 02 5B 52 52 52 52 52 52 ?? ?? ?? ?? ?? 89 E1 6A 1C }
		$socket = { 51 50 89 E1 6A 66 58 CD 80 D1 E3 B0 66 CD 80 57 43 B0 66 89 51 04 CD 80 }

	condition:
		3 of ($str*) and $ipv6 and $socket
}