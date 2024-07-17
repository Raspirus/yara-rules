rule ELASTIC_Windows_Wiper_Isaacwiper_239Cd2Dc : FILE MEMORY
{
	meta:
		description = "Detects Windows Wiper Isaacwiper (Windows.Wiper.IsaacWiper)"
		author = "Elastic Security"
		id = "239cd2dc-6f93-43fa-98e8-ad7a0edb8a8a"
		date = "2022-03-04"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Wiper_IsaacWiper.yar#L1-L24"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "13037b749aa4b1eda538fda26d6ac41c8f7b1d02d83f47b0d187dd645154e033"
		logic_hash = "102ffe215b1e1c39e1225cb39dfeb10a20a08c5b10f836490fc1501c6eb9e930"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a9c193d7c60b0c793c299b23f672d6428ceb229f2ceb2acbfc1124387954b244"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "C:\\ProgramData\\log.txt" wide fullword
		$a2 = "system physical drive -- FAILED" wide fullword
		$a3 = "-- system logical drive: " wide fullword
		$a4 = "start erasing system logical drive " wide fullword
		$a5 = "-- logical drive: " wide fullword
		$a6 = "-- start erasing logical drive " wide fullword

	condition:
		5 of them
}