rule ELASTIC_Windows_Hacktool_Winpeas_Ng_23Fee092 : FILE MEMORY
{
	meta:
		description = "WinPEAS detection based on the dotNet binary, File analysis module"
		author = "Elastic Security"
		id = "23fee092-f1ff-4d9e-9873-0a68360efb42"
		date = "2022-12-21"
		modified = "2023-02-01"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_WinPEAS_ng.yar#L89-L115"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
		logic_hash = "ed019c9198b5d9ff8392bfd7e0b23a7b1383eabce4c71c665a3ca4a943c8b6ee"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4420faa4da440a9e2b1d8eadef2a1864c078fccf391ac3d7872abe1d738c926e"
		threat_name = "Windows.Hacktool.WinPEAS-ng"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$win_0 = "File Analysis" ascii wide
		$win_1 = "apache*" ascii wide
		$win_2 = "tomcat*" ascii wide
		$win_3 = "had a timeout (ReDoS avoided but regex" ascii wide
		$win_4 = "Error looking for regex" ascii wide
		$win_5 = "Looking for secrets inside" ascii wide
		$win_6 = "files with ext" ascii wide
		$win_7 = "(limited to" ascii wide

	condition:
		4 of them
}