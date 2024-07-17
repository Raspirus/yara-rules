rule ELASTIC_Windows_Trojan_Diceloader_B32C6B99 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Diceloader (Windows.Trojan.Diceloader)"
		author = "Elastic Security"
		id = "b32c6b99-f634-4c6f-98f4-39954ef15afa"
		date = "2021-04-23"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Diceloader.yar#L1-L25"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a3b3f56a61c6dc8ba2aa25bdd9bd7dc2c5a4602c2670431c5cbc59a76e2b4c54"
		logic_hash = "f9e023f340edc4c46b2926e750c2ad3a3798e34415e43c0ea2d83073e3dc526a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "15d4bc57c03a560608ae69551aa46d1786072b3d78d747512f8ac3e6822a7b93"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "D$0GET " ascii fullword
		$a2 = "D$THostf" ascii fullword
		$a3 = "D$,POST" ascii fullword
		$a4 = "namef" ascii fullword
		$a5 = "send" ascii fullword
		$a6 = "log.ini" wide
		$a7 = { 70 61 73 73 00 00 65 6D 61 69 6C 00 00 6C 6F 67 69 6E 00 00 73 69 67 6E 69 6E 00 00 61 63 63 6F 75 6E 74 00 00 70 65 72 73 69 73 74 65 6E 74 00 00 48 6F 73 74 3A 20 }

	condition:
		all of them
}