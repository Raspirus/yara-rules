
rule ELASTIC_Windows_Hacktool_Sharpgpoabuse_14Ea480E : FILE MEMORY
{
	meta:
		description = "Detects Windows Hacktool Sharpgpoabuse (Windows.Hacktool.SharpGPOAbuse)"
		author = "Elastic Security"
		id = "14ea480e-fbd5-4dd3-885c-9a13bfb4400b"
		date = "2024-03-25"
		modified = "2024-05-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_SharpGPOAbuse.yar#L1-L26"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d13f87b9eaf09ef95778b2f1469aa34d03186d127c8f73c73299957d386c78d1"
		logic_hash = "efc1259f4ed05c8f41df75c056d36fd5a808a92b5c88cfb0522caedea39476b4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1f86d5dfc193076127dcc4355cbf0c4bdffc0785ca2daf8e1364d76ee273b343"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$name = "SharpGPOAbuse" wide fullword
		$s1 = "AddUserTask" wide fullword
		$s2 = "AddComputerTask" wide fullword
		$s3 = "AddComputerScript" wide fullword
		$s4 = "AddUserScript" wide fullword
		$s5 = "GPOName" wide fullword
		$s6 = "ScheduledTasks" wide fullword
		$s7 = "NewImmediateTask" wide fullword

	condition:
		($name and 1 of ($s*)) or all of ($s*)
}