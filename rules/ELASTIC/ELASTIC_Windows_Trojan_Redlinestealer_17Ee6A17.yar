
rule ELASTIC_Windows_Trojan_Redlinestealer_17Ee6A17 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Redlinestealer (Windows.Trojan.RedLineStealer)"
		author = "Elastic Security"
		id = "17ee6a17-161e-454a-baf1-2734995c82cd"
		date = "2021-06-12"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_RedLineStealer.yar#L1-L27"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "497bc53c1c75003fe4ae3199b0ff656c085f21dffa71d00d7a3a33abce1a3382"
		logic_hash = "0c868d0673c01e2c115d6822c34c877db77265251167f3a890a448a1de5c6a2d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a1f75937e83f72f61e027a1045374d3bd17cd387b223a6909b9aed52d2bc2580"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "RedLine.Logic.SQLite" ascii fullword
		$a2 = "RedLine.Reburn.Data.Browsers.Gecko" ascii fullword
		$a3 = "RedLine.Client.Models.Gecko" ascii fullword
		$b1 = "SELECT * FROM Win32_Process Where SessionId='{0}'" wide fullword
		$b2 = "get_encryptedUsername" ascii fullword
		$b3 = "https://icanhazip.com" wide fullword
		$b4 = "GetPrivate3Key" ascii fullword
		$b5 = "get_GrabTelegram" ascii fullword
		$b6 = "<GrabUserAgent>k__BackingField" ascii fullword

	condition:
		1 of ($a*) or all of ($b*)
}