rule ELASTIC_Windows_Trojan_Njrat_30F3C220 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Njrat (Windows.Trojan.Njrat)"
		author = "Elastic Security"
		id = "30f3c220-b8dc-45a1-bcf0-027c2f76fa63"
		date = "2021-06-13"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Njrat.yar#L1-L24"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "741a0f3954499c11f9eddc8df7c31e7c59ca41f1a7005646735b8b1d53438c1b"
		logic_hash = "76347165829415646f943bb984cd17ca138cf238d03f114c498dbcec081d5ae3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d15e131bca6beddcaecb20fffaff1784ad8a33a25e7ce90f7450d1a362908cc4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "get_Registry" ascii fullword
		$a2 = "SEE_MASK_NOZONECHECKS" wide fullword
		$a3 = "Download ERROR" wide fullword
		$a4 = "cmd.exe /c ping 0 -n 2 & del \"" wide fullword
		$a5 = "netsh firewall delete allowedprogram \"" wide fullword
		$a6 = "[+] System : " wide fullword

	condition:
		3 of them
}