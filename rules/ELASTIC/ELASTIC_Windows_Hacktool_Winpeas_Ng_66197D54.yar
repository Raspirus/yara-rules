
rule ELASTIC_Windows_Hacktool_Winpeas_Ng_66197D54 : FILE MEMORY
{
	meta:
		description = "WinPEAS detection based on the dotNet binary, application module"
		author = "Elastic Security"
		id = "66197d54-3cd2-4006-807d-24d0e0d9e25a"
		date = "2022-12-21"
		modified = "2023-02-01"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_WinPEAS_ng.yar#L1-L27"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
		logic_hash = "7bccf37960e2f197bb0021ecb12872f0f715b674d9774d02ec4e396f18963029"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "951f0ca036a0ab0cf2299382049eecb78f35325470f222c6db90a819b9414083"
		threat_name = "Windows.Hacktool.WinPEAS-ng"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$win_0 = "Possible DLL Hijacking, folder is writable" ascii wide
		$win_1 = "FolderPerms:.*" ascii wide
		$win_2 = "interestingFolderRights" ascii wide
		$win_3 = "(Unquoted and Space detected)" ascii wide
		$win_4 = "interestingFolderRights" ascii wide
		$win_5 = "RegPerms: .*" ascii wide
		$win_6 = "Permissions file: {3}" ascii wide
		$win_7 = "Permissions folder(DLL Hijacking):" ascii wide

	condition:
		4 of them
}