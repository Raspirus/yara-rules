rule ELASTIC_Windows_Trojan_Xtremerat_Cd5B60Be : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Xtremerat (Windows.Trojan.XtremeRAT)"
		author = "Elastic Security"
		id = "cd5b60be-4685-425a-8fe1-8366c0e5b84a"
		date = "2022-03-15"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_XtremeRAT.yar#L1-L28"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "735f7bf255bdc5ce8e69259c8e24164e5364aeac3ee78782b7b5275c1d793da8"
		logic_hash = "a6997ae4842bd45c440925ef2a5848b57c58e2373c0971ce6b328ea297ee97b4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2ee35d7c34374e9f5cffceb36fe1912932288ea4e8211a8b77430b98a9d41fb2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$s01 = "SOFTWARE\\XtremeRAT" wide fullword
		$s02 = "XTREME" wide fullword
		$s03 = "STARTSERVERBUFFER" wide fullword
		$s04 = "ENDSERVERBUFFER" wide fullword
		$s05 = "ServerKeyloggerU" ascii fullword
		$s06 = "TServerKeylogger" ascii fullword
		$s07 = "XtremeKeylogger" wide fullword
		$s08 = "XTREMEBINDER" wide fullword
		$s09 = "UnitInjectServer" ascii fullword
		$s10 = "shellexecute=" wide fullword

	condition:
		7 of ($s*)
}