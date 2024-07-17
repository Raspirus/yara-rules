
rule ELASTIC_Windows_Trojan_Onlylogger_B9E88336 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Onlylogger (Windows.Trojan.OnlyLogger)"
		author = "Elastic Security"
		id = "b9e88336-9719-4f43-afc9-b0e6c7d72b6f"
		date = "2022-03-22"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_OnlyLogger.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "69876ee4d89ba68ee86f1a4eaf0a7cb51a012752e14c952a177cd5ffd8190986"
		logic_hash = "b8d1c4c1e33fc0b54a62f82b8f53c9a1b051ad8c2f578d2a43f504158d1d9247"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5c8c98b250252d178c8dbad60bf398489d9396968e33b3e004219a4f323eeed8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "C:\\Users\\Ddani\\source\\repos\\onlyLogger\\Release\\onlyLogger.pdb" ascii fullword
		$b1 = "iplogger.org" ascii fullword
		$b2 = "NOT elevated" ascii fullword
		$b3 = "WinHttpSendRequest" ascii fullword

	condition:
		1 of ($a*) or all of ($b*)
}