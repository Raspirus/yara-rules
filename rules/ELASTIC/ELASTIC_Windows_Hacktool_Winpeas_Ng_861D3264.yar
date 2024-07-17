
rule ELASTIC_Windows_Hacktool_Winpeas_Ng_861D3264 : FILE MEMORY
{
	meta:
		description = "WinPEAS detection based on the dotNet binary, File Info module"
		author = "Elastic Security"
		id = "861d3264-34c3-4ff0-bdd3-44cb5ecce2c8"
		date = "2022-12-21"
		modified = "2023-02-01"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_WinPEAS_ng.yar#L117-L145"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
		logic_hash = "e6a0a0a24c70d69c0aa56063d2db0f5a0fedcda5b96d945ac14520524b1d00fd"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "03803621b6c9856443809889a14f1d2fa217812007878dd6cf9c3dc9e5f78f65"
		threat_name = "Windows.Hacktool.WinPEAS-ng"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$win_0 = "ConsoleHost_history.txt" ascii wide
		$win_1 = "Interesting files and registry" ascii wide
		$win_2 = "Cloud Credentials" ascii wide
		$win_3 = "Accessed:{2} -- Size:{3}" ascii wide
		$win_4 = "Unattend Files" ascii wide
		$win_5 = "Looking for common SAM" ascii wide
		$win_6 = "Found installed WSL distribution" ascii wide
		$win_7 = "Check skipped, if you want to run it" ascii wide
		$win_8 = "Cached GPP Passwords" ascii wide
		$win_9 = "[cC][rR][eE][dD][eE][nN][tT][iI][aA][lL]|[pP][aA][sS][sS][wW][oO]" ascii wide

	condition:
		5 of them
}