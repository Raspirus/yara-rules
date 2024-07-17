
rule ELASTIC_Windows_Trojan_Suddenicon_Ac021Ae0 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Suddenicon (Windows.Trojan.SuddenIcon)"
		author = "Elastic Security"
		id = "ac021ae0-67c6-45cf-a467-eb3c2b84b3e4"
		date = "2023-03-30"
		modified = "2023-03-30"
		reference = "https://www.elastic.co/security-labs/elastic-users-protected-from-suddenicon-supply-chain-attack"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_SuddenIcon.yar#L50-L76"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "033eabdd8ce8ecc4e1a657161c1f298c7dfe536ee2dbf9375cfda894638a7bee"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "115d4fc78bae7b5189a94b82ffd6547dfe89cfb66bf59d0e1d77c10fb937d2f7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "%s\\%s\\%s\\%s" wide fullword
		$str2 = "%s.old" wide fullword
		$str3 = "\n******************************** %s ******************************\n\n" wide fullword
		$str4 = "HostName: %s\\r\\nDomainName: %s\\r\\nOsVersion: %d.%d.%d\\r\\n\\r\\n" wide fullword
		$str5 = "%s\\r\\nDomainName: %s\\r\\nOsVersion: %d.%d.%d\\r\\n\\r\\n" wide fullword
		$str6 = "AppData\\Local\\Google\\Chrome\\User Data" wide fullword
		$str7 = "SELECT url, title FROM urls ORDER BY id DESC LIMIT 500" wide fullword
		$str8 = "SELECT url, title FROM moz_places ORDER BY id DESC LIMIT 500" wide fullword
		$b1 = "\\3CXDesktopApp\\config.json" wide fullword

	condition:
		6 of ($str*) or 1 of ($b*)
}