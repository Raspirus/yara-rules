rule ELASTIC_Windows_Trojan_Onlylogger_Ec14D5F2 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Onlylogger (Windows.Trojan.OnlyLogger)"
		author = "Elastic Security"
		id = "ec14d5f2-5716-47f3-a7fb-98ec2d8679d1"
		date = "2022-03-22"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_OnlyLogger.yar#L24-L46"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f45adcc2aad5c0fd900df4521f404bc9ca71b01e3378a5490f5ae2f0c711912e"
		logic_hash = "2838851a5e013705b64625801d2ab1d56cfc17c52f75a5fd71448cb0a4b4b683"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c69da3dfe0a464665759079207fbc0c82e690d812b38c83d3f4cd5998ecee1ff"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "KILLME" ascii fullword
		$a2 = "%d-%m-%Y %H" ascii fullword
		$a3 = "/c taskkill /im \"" ascii fullword
		$a4 = "\" /f & erase \"" ascii fullword
		$a5 = "/info.php?pub=" ascii fullword

	condition:
		all of them
}