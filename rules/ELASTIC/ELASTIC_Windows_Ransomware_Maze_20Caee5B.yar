
rule ELASTIC_Windows_Ransomware_Maze_20Caee5B : BETA FILE MEMORY
{
	meta:
		description = "Identifies MAZE ransomware"
		author = "Elastic Security"
		id = "20caee5b-cf7f-4db7-8c3b-67baf63bfc32"
		date = "2020-04-18"
		modified = "2021-08-23"
		reference = "https://www.bleepingcomputer.com/news/security/it-services-giant-cognizant-suffers-maze-ransomware-cyber-attack/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Maze.yar#L46-L71"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "e09c059b285d2176aeba1a1f70d39f13cef4e05dc023c7db25fb9d92bd9a67d9"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "47525839e0800f6edec6ad4580682a336e36f7d13bd9e7214eca0f16941016b8"
		threat_name = "Windows.Ransomware.Maze"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "Win32_ShadowCopy.id='%s'" wide fullword
		$a2 = "\"%s\" shadowcopy delete" wide fullword
		$a3 = "%spagefile.sys" wide fullword
		$a4 = "%sswapfile.sys" wide fullword
		$a5 = "Global\\%s" wide fullword
		$a6 = "DECRYPT-FILES.txt" wide fullword
		$a7 = "process call create \"cmd /c start %s\"" wide fullword

	condition:
		4 of ($a*)
}