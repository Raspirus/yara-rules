
rule ELASTIC_Macos_Trojan_Eggshell_Ddacf7B9 : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Eggshell (MacOS.Trojan.Eggshell)"
		author = "Elastic Security"
		id = "ddacf7b9-8479-47ef-9df2-17060578a8e5"
		date = "2021-09-30"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Eggshell.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6d93a714dd008746569c0fbd00fadccbd5f15eef06b200a4e831df0dc8f3d05b"
		logic_hash = "f986f7d1e3a68e27f82048017c6d6381a0354ffad2cd10f3eee69bbbfa940abd"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "2e6284c8e44809d5f88781dcf7779d1e24ce3aedd5e8db8598e49c01da63fe62"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a1 = "ScreenshotThread" ascii fullword
		$a2 = "KeylogThread" ascii fullword
		$a3 = "GetClipboardThread" ascii fullword
		$a4 = "_uploadProgress" ascii fullword
		$a5 = "killTask:" ascii fullword

	condition:
		all of them
}