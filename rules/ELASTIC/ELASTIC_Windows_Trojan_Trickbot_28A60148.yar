rule ELASTIC_Windows_Trojan_Trickbot_28A60148 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Trickbot (Windows.Trojan.Trickbot)"
		author = "Elastic Security"
		id = "28a60148-2efb-4cd2-ada1-dd2ae2699adf"
		date = "2021-03-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L307-L324"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "20a26ed3f0da3a77867597494bf0069a2093ec19b1c5e179c0e7934c1b69d4b9"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c857aa792ef247bfcf81e75fb696498b1ba25c09fc04049223a6dfc09cc064b1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { C0 31 E8 83 7D 0C 00 89 44 24 38 0F 29 44 24 20 0F 29 44 24 10 0F 29 }

	condition:
		all of them
}