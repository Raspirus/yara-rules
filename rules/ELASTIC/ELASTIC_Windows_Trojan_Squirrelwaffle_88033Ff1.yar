rule ELASTIC_Windows_Trojan_Squirrelwaffle_88033Ff1 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Squirrelwaffle (Windows.Trojan.Squirrelwaffle)"
		author = "Elastic Security"
		id = "88033ff1-f9b1-4cdc-bb68-bd3a10027584"
		date = "2021-09-20"
		modified = "2022-01-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Squirrelwaffle.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "00d045c89934c776a70318a36655dcdd77e1fedae0d33c98e301723f323f234c"
		logic_hash = "695d7d411a4de23ba1517a06bda3ce73add37dca1e6fe9046e7c2dcae237389e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "94c0d8ce3e06cf02a6fb57c074ff0ef60346babcde43c61371d099b011d9fcf9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "start /i /min /b start /i /min /b start /i /min /b " ascii fullword
		$a2 = " HTTP/1.1" ascii fullword
		$a3 = "Host:" ascii fullword
		$a4 = "APPDATA" ascii fullword

	condition:
		all of them
}