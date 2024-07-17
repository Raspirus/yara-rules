
rule ELASTIC_Windows_Hacktool_Winpeas_Ng_Bcedc8B2 : FILE MEMORY
{
	meta:
		description = "WinPEAS detection based on the dotNet binary, User info module"
		author = "Elastic Security"
		id = "bcedc8b2-d9e1-45cd-94b4-a19a3ed8c0f9"
		date = "2022-12-21"
		modified = "2023-02-01"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_WinPEAS_ng.yar#L263-L291"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
		logic_hash = "7f0a6a9168b5ff7cc02ccadd211cc8096307651be65c2b3e7cc9fdbbde08ab9f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "039ea2f11596d6a8d5da05944796424ee6be66e16742676bbb2dc3fcf274cf4a"
		threat_name = "Windows.Hacktool.WinPEAS-ng"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$win_0 = "Users Information" ascii wide
		$win_1 = "docker|Remote |DNSAdmins|AD Recycle Bin|" ascii wide
		$win_2 = "NotChange|NotExpi" ascii wide
		$win_3 = "Current Token privileges" ascii wide
		$win_4 = "Clipboard text" ascii wide
		$win_5 = "{0,-10}{1,-15}{2,-15}{3,-25}{4,-10}{5}" ascii wide
		$win_6 = "Ever logged users" ascii wide
		$win_7 = "Some AutoLogon credentials were found" ascii wide
		$win_8 = "Current User Idle Time" ascii wide
		$win_9 = "DsRegCmd.exe /status" ascii wide

	condition:
		5 of them
}