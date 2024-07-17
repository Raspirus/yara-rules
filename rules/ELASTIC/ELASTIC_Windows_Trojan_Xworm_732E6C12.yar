
rule ELASTIC_Windows_Trojan_Xworm_732E6C12 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Xworm (Windows.Trojan.Xworm)"
		author = "Elastic Security"
		id = "732e6c12-9ee0-4d04-a6e4-9eef874e2716"
		date = "2023-04-03"
		modified = "2023-04-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Xworm.yar#L1-L25"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "bf5ea8d5fd573abb86de0f27e64df194e7f9efbaadd5063dee8ff9c5c3baeaa2"
		logic_hash = "6aa72029eeeb2edd2472bf0db80b9c0ae4033d7d977cbee75ac94414d1cdff7a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "afbef8e590105e16bbd87bd726f4a3391cd6a4489f7a4255ba78a3af761ad2f0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "startsp" ascii wide fullword
		$str2 = "injRun" ascii wide fullword
		$str3 = "getinfo" ascii wide fullword
		$str4 = "Xinfo" ascii wide fullword
		$str5 = "openhide" ascii wide fullword
		$str6 = "WScript.Shell" ascii wide fullword
		$str7 = "hidefolderfile" ascii wide fullword

	condition:
		all of them
}