
rule ELASTIC_Linux_Trojan_Metasploit_B957E45D : FILE MEMORY
{
	meta:
		description = "Detects x86 msfvenom nonx TCP reverse shells"
		author = "Elastic Security"
		id = "b957e45d-0eb6-4580-af84-98608bbc34ef"
		date = "2024-05-07"
		modified = "2024-05-21"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Metasploit.yar#L95-L115"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "78af84bad4934283024f4bf72dfbf9cc081d2b92a9de32cc36e1289131c783ab"
		logic_hash = "27281303d007e6723308e88f335f52723b3ff0ef733d1a0712f5ba268e53a073"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ac71352e2b4c8ee8917b1469cd33e6b54eb4cdcd96f02414465127c5cad6b710"
		threat_name = "Linux.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$str1 = { 31 DB 53 43 53 6A 02 6A 66 58 89 E1 CD 80 97 5B }
		$str2 = { 66 53 89 E1 6A 66 58 50 51 57 89 E1 43 CD 80 5B 99 B6 0C B0 03 CD 80 }

	condition:
		all of them
}