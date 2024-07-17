rule ELASTIC_Linux_Trojan_Metasploit_E5B61173 : FILE MEMORY
{
	meta:
		description = "Detects x86 msfvenom stageless TCP reverse shell payload"
		author = "Elastic Security"
		id = "e5b61173-cf1c-4176-bc43-550c0213ce98"
		date = "2024-05-07"
		modified = "2024-05-21"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Metasploit.yar#L399-L420"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8032a7a320102c8e038db16d51b8615ee49f04dab1444326463f75ce0c5947a5"
		logic_hash = "f60d2de0b7fac06b62616d7c7f51e9374df3895eb30a07040e742cbcb462a418"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7052cce595dbbf36aed5e1edab12a75f06059e6267c859516011d8feb9e328e6"
		threat_name = "Linux.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$str1 = { 31 DB F7 E3 53 43 53 6A 02 89 E1 B0 66 CD 80 93 59 B0 3F CD 80 49 79 }
		$str2 = { 89 E1 B0 66 50 51 53 B3 03 89 E1 CD 80 52 }
		$str3 = { 89 E3 52 53 89 E1 B0 0B CD 80 }

	condition:
		all of them
}