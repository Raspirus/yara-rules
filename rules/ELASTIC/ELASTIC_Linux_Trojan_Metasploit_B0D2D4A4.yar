rule ELASTIC_Linux_Trojan_Metasploit_B0D2D4A4 : FILE MEMORY
{
	meta:
		description = "Detects x86 msfvenom shell find port payloads"
		author = "Elastic Security"
		id = "b0d2d4a4-4fd6-4fc0-959b-89d6969215ed"
		date = "2024-05-07"
		modified = "2024-05-21"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Metasploit.yar#L184-L205"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a37c888875e84069763303476f0df6769df6015b33aded59fc1e23eb604f2163"
		logic_hash = "bcabf74900222074ecf9051b6e0cb4ca7a240acd047a1b27137d1d198e23f161"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f6d2e001d8cfb6f086327ddb457a964932a8200ff60ea973b26ac9fb909b4a9c"
		threat_name = "Linux.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$str1 = { 31 DB 53 89 E7 6A 10 54 57 53 89 E1 B3 07 FF 01 6A 66 58 CD 80 }
		$str2 = { 5B 6A 02 59 B0 3F CD 80 49 }
		$str3 = { 50 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 50 53 89 E1 99 B0 0B CD 80 }

	condition:
		all of them
}