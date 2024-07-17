
rule ELASTIC_Windows_Hacktool_Winpeas_Ng_4A9B9603 : FILE MEMORY
{
	meta:
		description = "WinPEAS detection based on the dotNet binary, Services info module"
		author = "Elastic Security"
		id = "4a9b9603-7b42-4a85-b66a-7f4ec0013338"
		date = "2022-12-21"
		modified = "2023-02-01"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_WinPEAS_ng.yar#L205-L231"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
		logic_hash = "8d78483b54d3be6988b1f5df826b8709b7aa2045ff3a3e754c359365d053bb27"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2a7b0e1d850fa6a24f590755ae5610309741e520e4b2bc067f54a8e086444da2"
		threat_name = "Windows.Hacktool.WinPEAS-ng"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$win_0 = "Services Information" ascii wide
		$win_1 = "Interesting Services -non Microsoft-" ascii wide
		$win_2 = "FilteredPath" ascii wide
		$win_3 = "YOU CAN MODIFY THIS SERVICE:" ascii wide
		$win_4 = "Modifiable Services" ascii wide
		$win_5 = "AccessSystemSecurity" ascii wide
		$win_6 = "Looks like you cannot change the" ascii wide
		$win_7 = "Checking write permissions in" ascii wide

	condition:
		4 of them
}