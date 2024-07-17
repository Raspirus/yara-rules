rule ELASTIC_Macos_Trojan_Thiefquest_86F9Ef0C : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Thiefquest (MacOS.Trojan.Thiefquest)"
		author = "Elastic Security"
		id = "86f9ef0c-832e-4e4a-bd39-c80c1d064dbe"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Thiefquest.yar#L44-L62"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "59fb018e338908eb69be72ab11837baebf8d96cdb289757f1f4977228e7640a0"
		logic_hash = "426d533d39e594123f742b15d0a93ded986b9b308685f7b2cfaf5de0b32cdbff"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e8849628ee5449c461f1170c07b6d2ebf4f75d48136f26b52bee9bcf4e164d5b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 6C 65 31 6A 6F 57 4E 33 30 30 30 30 30 33 33 00 30 72 7A 41 43 47 33 57 72 7C }

	condition:
		all of them
}