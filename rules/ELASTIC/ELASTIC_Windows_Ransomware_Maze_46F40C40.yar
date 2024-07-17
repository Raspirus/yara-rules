
rule ELASTIC_Windows_Ransomware_Maze_46F40C40 : BETA FILE MEMORY
{
	meta:
		description = "Identifies MAZE ransomware"
		author = "Elastic Security"
		id = "46f40c40-05a4-4163-a62d-675882149781"
		date = "2020-04-18"
		modified = "2021-10-04"
		reference = "https://www.bleepingcomputer.com/news/security/it-services-giant-cognizant-suffers-maze-ransomware-cyber-attack/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Maze.yar#L23-L44"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "99180f41aaaf1dfb0a8a40709dcc392fdbc2b2d3a4d4b4a1ab160dd5f2b4c703"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "efe1e0d23fbfd72fd2843a9c8d5e62394ef8c75b9a7bd03fdbb36e2cf97bf12e"
		threat_name = "Windows.Ransomware.Maze"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$b1 = "Dear %s, your files have been encrypted by RSA-2048 and ChaCha algorithms" wide fullword
		$b2 = "Maze Ransomware" wide fullword
		$b3 = "%s! Alert! %s! Alert! Dear %s Your files have been encrypted by %s! Attention! %s" wide fullword

	condition:
		2 of ($b*)
}