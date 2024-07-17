
rule ELASTIC_Windows_Trojan_Hancitor_6738D84A : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Hancitor (Windows.Trojan.Hancitor)"
		author = "Elastic Security"
		id = "6738d84a-7393-4db2-97cc-66f471b5699a"
		date = "2021-06-17"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Hancitor.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a674898f39377e538f9ec54197689c6fa15f00f51aa0b5cc75c2bafd86384a40"
		logic_hash = "448243b6925c4e419b1fd492ac5e8d43a7baa4492ba7a5a0b44bc8e036c77ec2"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "44a4dd7c35e0b4f3f161b82463d8f0ee113eaedbfabb7d914ce9486b6bd3a912"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d"
		$b1 = "Rundll32.exe %s, start" ascii fullword
		$b2 = "MASSLoader.dll" ascii fullword

	condition:
		$a1 or all of ($b*)
}