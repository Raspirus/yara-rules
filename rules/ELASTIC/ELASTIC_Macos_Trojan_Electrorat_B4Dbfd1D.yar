rule ELASTIC_Macos_Trojan_Electrorat_B4Dbfd1D : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Electrorat (MacOS.Trojan.Electrorat)"
		author = "Elastic Security"
		id = "b4dbfd1d-4968-4121-a4c2-5935b7f76fc1"
		date = "2021-09-30"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Electrorat.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b1028b38fcce0d54f2013c89a9c0605ccb316c36c27faf3a35adf435837025a4"
		logic_hash = "a36143a8c93cb187dba0a88a15550219c19f1483502f782dfefc1e53829cfbf1"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "fa65fc0a8f5b1f63957c586e6ca8e8fbdb811970f25a378a4ff6edf5e5c44da7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a1 = "_TtC9Keylogger9Keylogger" ascii fullword
		$a2 = "_TtC9Keylogger17CallBackFunctions" ascii fullword
		$a3 = "\\DELETE-FORWARD" ascii fullword
		$a4 = "\\CAPSLOCK" ascii fullword

	condition:
		all of them
}