
rule ELASTIC_Windows_Trojan_Remcos_7591E9F1 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Remcos (Windows.Trojan.Remcos)"
		author = "Elastic Security"
		id = "7591e9f1-452d-4731-9bec-545fb0272c80"
		date = "2023-06-23"
		modified = "2023-07-10"
		reference = "https://www.elastic.co/security-labs/exploring-the-ref2731-intrusion-set"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Remcos.yar#L25-L49"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4e6e5ecd1cf9c88d536c894d74320c77967fe08c75066098082bf237283842fa"
		logic_hash = "96acf1ba7740a8d34d929ed4a4fa446c984c3a8f64a603d428e782b6997e4d20"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9436c314f89a09900a9b3c2fd9bab4a0423912427cf47b71edce5eba31132449"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "ServRem" ascii fullword
		$a2 = "Screenshots" ascii fullword
		$a3 = "MicRecords" ascii fullword
		$a4 = "remcos.exe" wide nocase fullword
		$a5 = "Remcos" wide fullword
		$a6 = "logs.dat" wide fullword

	condition:
		3 of them
}