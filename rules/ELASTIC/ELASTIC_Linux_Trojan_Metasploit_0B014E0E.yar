rule ELASTIC_Linux_Trojan_Metasploit_0B014E0E : FILE MEMORY
{
	meta:
		description = "Detects x64 msfvenom exec payloads"
		author = "Elastic Security"
		id = "0b014e0e-3f5a-4dcc-8860-eb101281b8a5"
		date = "2024-05-07"
		modified = "2024-05-21"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Metasploit.yar#L279-L303"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a24443331508cc72b3391353f91cd009cafcc223ac5939eab12faf57447e3162"
		logic_hash = "cb19a0461d5fe6066d1fed4898ea12a9818be69d870e511559b19d5c7c959819"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7a61a0e169bf6aa8760b42c5b260dee453ea6a85fe9e5da46fb7598994904747"
		threat_name = "Linux.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$payload1 = { 48 B8 2F [0-1] 62 69 6E 2F 73 68 ?? ?? 50 54 5F 52 5E 6A 3B 58 0F 05 }
		$payload2a = { 48 B8 2F 2F 62 69 6E 2F 73 68 99 EB ?? 5D 52 5B }
		$payload2b = { 54 5E 52 50 54 5F 52 55 56 57 54 5E 6A 3B 58 0F 05 }
		$payload3a = { 48 B8 2F 62 69 6E 2F 73 68 00 99 50 54 5F 52 }
		$payload3b = { 54 5E 52 E8 }
		$payload3c = { 56 57 54 5E 6A 3B 58 0F 05 }

	condition:
		$payload1 or ( all of ($payload2*)) or ( all of ($payload3*))
}