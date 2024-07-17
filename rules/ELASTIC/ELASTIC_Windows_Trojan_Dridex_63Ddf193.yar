rule ELASTIC_Windows_Trojan_Dridex_63Ddf193 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Dridex (Windows.Trojan.Dridex)"
		author = "Elastic Security"
		id = "63ddf193-31a6-4139-b452-960fe742da93"
		date = "2021-08-07"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Dridex.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b1d66350978808577159acc7dc7faaa273e82c103487a90bf0d040afa000cb0d"
		logic_hash = "e792f4693be0a7c71d1e638212a8fb3acb1e14dedd48218861fad8c09811da29"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7b4c5fde8e107a67ff22f3012200e56ec452e0a57a49edb2e06ee225ecfe228c"
		severity = 90
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "snxhk.dll" ascii fullword
		$a2 = "LondLibruryA" ascii fullword

	condition:
		all of them
}