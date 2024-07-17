rule ELASTIC_Windows_Hacktool_Winpeas_Ng_4Db2C852 : FILE MEMORY
{
	meta:
		description = "WinPEAS detection based on the dotNet binary, System info module"
		author = "Elastic Security"
		id = "4db2c852-6c03-4672-9250-f80671b93e1b"
		date = "2022-12-21"
		modified = "2023-02-01"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_WinPEAS_ng.yar#L233-L261"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
		logic_hash = "88c88103a055d25ba97f08e2f47881001ad8a2200a33ac04246494963dfe6638"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f05862b7b74cb4741aa953d725336005cdb9b1d50a92ce8bb295114e27f81b2a"
		threat_name = "Windows.Hacktool.WinPEAS-ng"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$win_0 = "No prompting|PromptForNonWindowsBinaries" ascii wide
		$win_1 = "System Information" ascii wide
		$win_2 = "Showing All Microsoft Updates" ascii wide
		$win_3 = "GetTotalHistoryCount" ascii wide
		$win_4 = "PS history size:" ascii wide
		$win_5 = "powershell_transcript*" ascii wide
		$win_6 = "Check what is being logged" ascii wide
		$win_7 = "WEF Settings" ascii wide
		$win_8 = "CredentialGuard is active" ascii wide
		$win_9 = "cachedlogonscount is" ascii wide

	condition:
		5 of them
}