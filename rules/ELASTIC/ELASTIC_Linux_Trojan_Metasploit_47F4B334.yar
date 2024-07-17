
rule ELASTIC_Linux_Trojan_Metasploit_47F4B334 : FILE MEMORY
{
	meta:
		description = "Detects x86 msfvenom exec payloads"
		author = "Elastic Security"
		id = "47f4b334-619b-4b9c-841d-b00c09dd98e5"
		date = "2024-05-07"
		modified = "2024-05-21"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Metasploit.yar#L253-L277"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c3821f63a7ec8861a6168b4bb494bf8cbac436b3abf5eaffbc6907fd68ebedb8"
		logic_hash = "34c8182d3b5ecbebd122d2d58fc0502a6bbca020b528ffdcc9ee988f21512d99"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "955d65f1097ec9183db8bd3da43090f579a27461ba345bb74f62426734731184"
		threat_name = "Linux.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$payload1 = { 31 C9 F7 E1 B0 0B [0-1] 68 2F ?? ?? ?? 68 2F 62 69 6E 89 E3 CD 80 }
		$payload2a = { 31 DB F7 E3 B0 0B 52 }
		$payload2b = { 88 14 1E 52 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 52 56 57 53 89 E1 CD 80 }
		$payload3a = { 6A 0B 58 99 52 }
		$payload3b = { 89 E7 68 2F 73 68 00 68 2F 62 69 6E 89 E3 52 E8 }
		$payload3c = { 57 53 89 E1 CD 80 }

	condition:
		$payload1 or ( all of ($payload2*)) or ( all of ($payload3*))
}