rule ELASTIC_Windows_Hacktool_Winpeas_Ng_Cae025B1 : FILE MEMORY
{
	meta:
		description = "WinPEAS detection based on the dotNet binary, Process info module"
		author = "Elastic Security"
		id = "cae025b1-bc2a-4eea-a1c1-c82d6e4fd71f"
		date = "2022-12-21"
		modified = "2023-02-01"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_WinPEAS_ng.yar#L177-L203"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
		logic_hash = "9c34443cffed43513242321e2170484dbb0d41b251aee8ea640d44da76918122"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3e407824b258ef66ac6883d4c5dd3efeb0f744f8f64b099313cf83e96f9e968a"
		threat_name = "Windows.Hacktool.WinPEAS-ng"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$win_0 = "Processes Information" ascii wide
		$win_1 = "Interesting Processes -non Microsoft-" ascii wide
		$win_2 = "Permissions:.*" ascii wide
		$win_3 = "Possible DLL Hijacking.*" ascii wide
		$win_4 = "ExecutablePath" ascii wide
		$win_5 = "Vulnerable Leaked Handlers" ascii wide
		$win_6 = "Possible DLL Hijacking folder:" ascii wide
		$win_7 = "Command Line:" ascii wide

	condition:
		5 of them
}