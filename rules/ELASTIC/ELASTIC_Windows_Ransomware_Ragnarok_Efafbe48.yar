rule ELASTIC_Windows_Ransomware_Ragnarok_Efafbe48 : BETA FILE MEMORY
{
	meta:
		description = "Identifies RAGNAROK ransomware"
		author = "Elastic Security"
		id = "efafbe48-7740-4c21-b585-467f7ad76f8d"
		date = "2020-05-03"
		modified = "2021-08-23"
		reference = "https://twitter.com/malwrhunterteam/status/1256263426441125888?s=20"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Ragnarok.yar#L44-L71"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "c9d203620e0e6e04d717595ca70a5e5efa74abfc11e4e732d729caab2d246c27"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "a1535bc01756ac9e986eb564d712b739df980ddd61cfde5a7b001849a6b07b57"
		threat_name = "Windows.Ransomware.Ragnarok"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "cmd_firewall" ascii fullword
		$a2 = "cmd_recovery" ascii fullword
		$a3 = "cmd_boot" ascii fullword
		$a4 = "cmd_shadow" ascii fullword
		$a5 = "readme_content" ascii fullword
		$a6 = "readme_name" ascii fullword
		$a8 = "rg_path" ascii fullword
		$a9 = "cometosee" ascii fullword
		$a10 = "&prv_ip=" ascii fullword

	condition:
		6 of ($a*)
}