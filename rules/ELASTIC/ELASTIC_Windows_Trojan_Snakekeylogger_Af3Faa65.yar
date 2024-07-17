rule ELASTIC_Windows_Trojan_Snakekeylogger_Af3Faa65 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Snakekeylogger (Windows.Trojan.SnakeKeylogger)"
		author = "Elastic Security"
		id = "af3faa65-b19d-4267-ac02-1a3b50cdc700"
		date = "2021-04-06"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_SnakeKeylogger.yar#L1-L32"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "54180a642d40b5366f1b400c347c25dc31397d662d6bb8af33c7d2319c97d3fb"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "15f4ef2a03c6f5c6284ea6a9013007e4ea7dc90a1ba9c81a53a1c7407d85890d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "get_encryptedPassword" ascii fullword
		$a2 = "get_encryptedUsername" ascii fullword
		$a3 = "get_timePasswordChanged" ascii fullword
		$a4 = "get_passwordField" ascii fullword
		$a5 = "set_encryptedPassword" ascii fullword
		$a6 = "get_passwords" ascii fullword
		$a7 = "get_logins" ascii fullword
		$a8 = "GetOutlookPasswords" ascii fullword
		$a9 = "StartKeylogger" ascii fullword
		$a10 = "KeyLoggerEventArgs" ascii fullword
		$a11 = "KeyLoggerEventArgsEventHandler" ascii fullword
		$a12 = "GetDataPassword" ascii fullword
		$a13 = "_encryptedPassword" ascii fullword
		$b1 = "----------------S--------N--------A--------K--------E----------------"
		$c1 = "SNAKE-KEYLOGGER" ascii fullword

	condition:
		8 of ($a*) or #b1>5 or #c1>5
}