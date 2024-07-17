rule ELASTIC_Windows_Trojan_Danabot_6F3Dadb2 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Danabot (Windows.Trojan.Danabot)"
		author = "Elastic Security"
		id = "6f3dadb2-3283-4333-8143-1265721d2221"
		date = "2021-08-15"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Danabot.yar#L1-L26"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "716e5a3d29ff525aed30c18061daff4b496f3f828ba2ac763efd857062a42e96"
		logic_hash = "b9c895be9eab775726abd2c13256d598c5b79bceb2d652c30b1df4cfc37e4b93"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "387e3fb3c3f625c8b5e42052c126ce4dbb7de3a7de6b68addf0a0777b9d3b504"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "%s.dll" ascii fullword
		$a2 = "del_ini://Main|Password|" wide fullword
		$a3 = "S-Password.txt" wide fullword
		$a4 = "BiosTime:" wide fullword
		$a5 = "%lu:%s:%s:%d:%s" ascii fullword
		$a6 = "DNS:%s" ascii fullword
		$a7 = "THttpInject&" ascii fullword
		$a8 = "TCookies&" ascii fullword

	condition:
		all of them
}