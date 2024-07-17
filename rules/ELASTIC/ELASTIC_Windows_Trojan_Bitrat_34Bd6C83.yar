rule ELASTIC_Windows_Trojan_Bitrat_34Bd6C83 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Bitrat (Windows.Trojan.Bitrat)"
		author = "Elastic Security"
		id = "34bd6c83-9a71-43d5-b0b1-1646a8fb66e8"
		date = "2021-06-13"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Bitrat.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "37f70ae0e4e671c739d402c00f708761e98b155a1eefbedff1236637c4b7690a"
		logic_hash = "d386fc2a4b6a98638328d1aa05a8d8dbb7a1bbcd72943457b1a5a27b056744ef"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "bc4a5fad1810ad971277a455030eed3377901a33068bb994e235346cfe5a524f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "crd_logins_report" ascii fullword
		$a2 = "drives_get" ascii fullword
		$a3 = "files_get" ascii fullword
		$a4 = "shell_stop" ascii fullword
		$a5 = "hvnc_start_ie" ascii fullword

	condition:
		all of them
}