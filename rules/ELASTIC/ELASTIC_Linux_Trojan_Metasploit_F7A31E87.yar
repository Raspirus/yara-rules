rule ELASTIC_Linux_Trojan_Metasploit_F7A31E87 : FILE MEMORY
{
	meta:
		description = "Detects x86 msfvenom shell find tag payloads"
		author = "Elastic Security"
		id = "f7a31e87-c3d7-4a26-9879-68893780283e"
		date = "2024-05-07"
		modified = "2024-05-21"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Metasploit.yar#L161-L182"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "82b55d8c0f0175d02399aaf88ad9e92e2e37ef27d52c7f71271f3516ba884847"
		logic_hash = "49583ba4f2bedb9337a8c10df4246bb76a3e60b08ba1a6b8684537fee985d911"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7171cb9989405be295479275d8824ced7e3616097db88e3b0f8f1ef6798607e2"
		threat_name = "Linux.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$setup = { 31 DB 53 89 E6 6A 40 B7 0A 53 56 53 89 E1 86 FB 66 FF 01 6A 66 58 CD 80 81 3E }
		$payload1 = { 5F FC AD FF }
		$payload2 = { 5F 89 FB 6A 02 59 6A 3F 58 CD 80 49 79 ?? 6A 0B 58 99 52 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 52 53 89 E1 CD 80 }

	condition:
		$setup and 1 of ($payload*)
}