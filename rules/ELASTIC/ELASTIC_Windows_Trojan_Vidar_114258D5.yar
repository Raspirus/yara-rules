
rule ELASTIC_Windows_Trojan_Vidar_114258D5 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Vidar (Windows.Trojan.Vidar)"
		author = "Elastic Security"
		id = "114258d5-f05e-46ac-914b-1a7f338ccf58"
		date = "2021-06-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Vidar.yar#L21-L44"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "34c0cb6eaf2171d3ab9934fe3f962e4e5f5e8528c325abfe464d3c02e5f939ec"
		logic_hash = "9ea3ea0533d14edd0332fa688497efd566a890d1507214fc8591a0a11433d060"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9b4f7619e15398fcafc622af821907e4cf52964c55f6a447327738af26769934"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "BinanceChainWallet" fullword
		$a2 = "*wallet*.dat" fullword
		$a3 = "SOFTWARE\\monero-project\\monero-core" fullword
		$b1 = "CC\\%s_%s.txt" fullword
		$b2 = "History\\%s_%s.txt" fullword
		$b3 = "Autofill\\%s_%s.txt" fullword

	condition:
		1 of ($a*) and 1 of ($b*)
}