
rule ELASTIC_Windows_Hacktool_Winpeas_Ng_94474B0B : FILE MEMORY
{
	meta:
		description = "WinPEAS detection based on the bat script"
		author = "Elastic Security"
		id = "94474b0b-c3dc-4585-afb3-3afe4c3ec525"
		date = "2022-12-21"
		modified = "2023-02-01"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_WinPEAS_ng.yar#L323-L351"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
		logic_hash = "e209c9ce1f4b11c5fdeade3298329d62f5cf561403c87077d94b6921e81ffaea"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "06e184fb837274271711288994a3e6bfcc2a50472ca05c8af9f1e4d8efd9091d"
		threat_name = "Windows.Hacktool.WinPEAS-ng"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$win_0 = "Windows local Privilege Escalation Awesome Script" ascii wide
		$win_1 = "BASIC SYSTEM INFO" ascii wide
		$win_2 = "LAPS installed?" ascii wide
		$win_3 = "Check for services restricted from the outside" ascii wide
		$win_4 = "CURRENT USER" ascii wide
		$win_5 = "hacktricks.xyz" ascii wide
		$win_6 = "SERVICE VULNERABILITIES" ascii wide
		$win_7 = "DPAPI MASTER KEYS" ascii wide
		$win_8 = "Files in registry that may contain credentials" ascii wide
		$win_9 = "SAM and SYSTEM backups" ascii wide

	condition:
		6 of them
}