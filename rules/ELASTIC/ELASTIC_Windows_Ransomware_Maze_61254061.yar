
rule ELASTIC_Windows_Ransomware_Maze_61254061 : BETA FILE MEMORY
{
	meta:
		description = "Identifies MAZE ransomware"
		author = "Elastic Security"
		id = "61254061-e8af-47ab-9cce-96debd99a80a"
		date = "2020-04-18"
		modified = "2021-08-23"
		reference = "https://www.bleepingcomputer.com/news/security/it-services-giant-cognizant-suffers-maze-ransomware-cyber-attack/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Maze.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "b8537add953cdd7bc6adbff97f7f5a94de028709f0bd71102ee96d26d55f4f20"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "670d9abbdea153ca66f24ef6806f97e9af3efb73f621167e95606da285627d1b"
		threat_name = "Windows.Ransomware.Maze"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$c1 = { FC 8B 55 08 8B 44 8A 10 C1 E0 09 8B 4D FC 8B 55 08 8B 4C 8A 10 C1 }
		$c2 = { 72 F0 0C 66 0F 72 D4 14 66 0F EB C4 66 0F 70 E0 39 66 0F FE E6 66 0F 70 }

	condition:
		1 of ($c*)
}