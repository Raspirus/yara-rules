
rule ELASTIC_Windows_Hacktool_Winpeas_Ng_413Caa6B : FILE MEMORY
{
	meta:
		description = "WinPEAS detection based on the dotNet binary, event module"
		author = "Elastic Security"
		id = "413caa6b-90b7-4763-97b3-49aeb5a97cf6"
		date = "2022-12-21"
		modified = "2023-02-01"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_WinPEAS_ng.yar#L59-L87"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
		logic_hash = "4f2417d61be5e68630408a151cd73372aef9e7f4638acf4e80bfa5b2811119a7"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "80b32022a69be8fc1d7e146c3c03623b51e2ee4206eb5f70be753477d68800d5"
		threat_name = "Windows.Hacktool.WinPEAS-ng"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$win_0 = "Interesting Events information" ascii wide
		$win_1 = "PowerShell events" ascii wide
		$win_2 = "Created (UTC)" ascii wide
		$win_3 = "Printing Account Logon Events" ascii wide
		$win_4 = "Subject User Name" ascii wide
		$win_5 = "Target User Name" ascii wide
		$win_6 = "NTLM relay might be possible" ascii wide
		$win_7 = "You can obtain NetNTLMv2" ascii wide
		$win_8 = "The following users have authenticated" ascii wide
		$win_9 = "You must be an administrator" ascii wide

	condition:
		5 of them
}