rule ELASTIC_Windows_Hacktool_Winpeas_Ng_E8Ed269C : FILE MEMORY
{
	meta:
		description = "WinPEAS detection based on the dotNet binary, checks module"
		author = "Elastic Security"
		id = "e8ed269c-3191-44c0-a9c6-55172fb59c8c"
		date = "2022-12-21"
		modified = "2023-02-01"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_WinPEAS_ng.yar#L29-L57"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
		logic_hash = "c56b6dfb2c3ae657615c825a4d5d5640c2204fa4217262e1ccb4359d5a914a63"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7b6ede4d95b2d6d2a43e729365adb9de3fde74ed731cafdb88916ac3925f9164"
		threat_name = "Windows.Hacktool.WinPEAS-ng"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$win_0 = "systeminfo" ascii wide
		$win_1 = "Please specify a valid log file." ascii wide
		$win_2 = "argument present, redirecting output" ascii wide
		$win_3 = "max-regex-file-size" ascii wide
		$win_4 = "-lolbas" ascii wide
		$win_5 = "[!] the provided linpeas.sh url:" ascii wide
		$win_6 = "sensitive_files yaml" ascii wide
		$win_7 = "Getting Win32_UserAccount" ascii wide
		$win_8 = "(local + domain)" ascii wide
		$win_9 = "Creating AppLocker bypass" ascii wide

	condition:
		5 of them
}