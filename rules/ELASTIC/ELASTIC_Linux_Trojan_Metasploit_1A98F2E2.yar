
rule ELASTIC_Linux_Trojan_Metasploit_1A98F2E2 : FILE MEMORY
{
	meta:
		description = "Detects x86 msfvenom nonx TCP bind shells"
		author = "Elastic Security"
		id = "1a98f2e2-9354-4d04-b1c0-d3998e54e2c4"
		date = "2024-05-07"
		modified = "2024-05-21"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Metasploit.yar#L117-L137"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "89be4507c9c24c4ec9a7282f197a9a6819e696d2832df81f7e544095d048fc22"
		logic_hash = "23ea1c255472a67746b470e50d982bc91d22ede5e2582cf5cfaa90a1ed4e8805"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b9865aad13b4d837e7541fe6a501405aa7d694c8fefd96633c0239031ebec17a"
		threat_name = "Linux.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$str1 = { 31 DB 53 43 53 6A 02 6A 66 58 99 89 E1 CD 80 96 43 52 }
		$str2 = { 66 53 89 E1 6A 66 58 50 51 56 89 E1 CD 80 B0 66 D1 E3 CD 80 52 52 56 43 89 E1 B0 66 CD 80 93 B6 0C B0 03 CD 80 89 DF }

	condition:
		all of them
}