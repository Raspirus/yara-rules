rule ELASTIC_Windows_Trojan_Azorult_38Fce9Ea : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Azorult (Windows.Trojan.Azorult)"
		author = "Elastic Security"
		id = "38fce9ea-a94e-49d3-8eef-96fe06ad27f8"
		date = "2021-08-05"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Azorult.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "405d1e6196dc5be1f46a1bd07c655d1d4b36c32f965d9a1b6d4859d3f9b84491"
		logic_hash = "e23b21992b7ff577d4521c733929638522f4bf57b54c72e5e46196d028d6be26"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0655018fc803469c6d89193b75b4967fd02400fae07364ffcd11d1bc6cbbe74a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "/c %WINDIR%\\system32\\timeout.exe 3 & del \"" wide fullword
		$a2 = "%APPDATA%\\.purple\\accounts.xml" wide fullword
		$a3 = "%TEMP%\\curbuf.dat" wide fullword
		$a4 = "PasswordsList.txt" ascii fullword
		$a5 = "Software\\Valve\\Steam" wide fullword

	condition:
		all of them
}