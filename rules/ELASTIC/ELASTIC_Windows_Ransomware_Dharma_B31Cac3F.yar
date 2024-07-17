rule ELASTIC_Windows_Ransomware_Dharma_B31Cac3F : BETA FILE MEMORY
{
	meta:
		description = "Identifies DHARMA ransomware"
		author = "Elastic Security"
		id = "b31cac3f-6e04-48b2-9d16-1a6b66fa8012"
		date = "2020-06-25"
		modified = "2021-08-23"
		reference = "https://blog.malwarebytes.com/threat-analysis/2019/05/threat-spotlight-crysis-aka-dharma-ransomware-causing-a-crisis-for-businesses/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Dharma.yar#L23-L44"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "30500e35721e9db3d63cafa5ca10818557fa9f4e0bda9c0d02283183508cf7b5"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "25d23d045c57758dbb14092cff3cc190755ceb3a21c8a80505bd316a430e21fc"
		threat_name = "Windows.Ransomware.Dharma"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$b1 = "sssssbsss" ascii fullword
		$b2 = "sssssbs" ascii fullword
		$b3 = "RSDS%~m" ascii fullword

	condition:
		3 of ($b*)
}