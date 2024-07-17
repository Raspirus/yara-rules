rule ELASTIC_Linux_Trojan_Metasploit_2B0Ad6F0 : FILE MEMORY
{
	meta:
		description = "Detects x64 msfvenom find TCP port payloads"
		author = "Elastic Security"
		id = "2b0ad6f0-44d2-4e7e-8cca-2b0ae1b88d48"
		date = "2024-05-07"
		modified = "2024-05-21"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Metasploit.yar#L350-L371"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "aa2bce61511c72ac03562b5178aad57bce8b46916160689ed07693790cbfbeec"
		logic_hash = "91b4547e44c40cafe09dd415f0b5dfe5980fcb10d50aeae844cf21e7608d9a9d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b15da42f957107d54bfad78eff3a703cc2a54afcef8207d42292f2520690d585"
		threat_name = "Linux.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$str1 = { 48 31 FF 48 31 DB B3 18 48 29 DC 48 8D 14 24 48 C7 02 10 00 00 00 48 8D 74 24 08 6A 34 58 0F 05 48 FF C7 }
		$str2 = { 48 FF CF 6A 02 5E 6A 21 58 0F 05 48 FF CE 79 }
		$str3 = { 48 89 F3 BB 41 2F 73 68 B8 2F 62 69 6E 48 C1 EB 08 48 C1 E3 20 48 09 D8 50 48 89 E7 48 31 F6 48 89 F2 6A 3B 58 0F 05 }

	condition:
		all of them
}