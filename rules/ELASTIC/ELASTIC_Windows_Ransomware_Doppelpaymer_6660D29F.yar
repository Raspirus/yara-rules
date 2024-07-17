
rule ELASTIC_Windows_Ransomware_Doppelpaymer_6660D29F : BETA FILE MEMORY
{
	meta:
		description = "Identifies DOPPELPAYMER ransomware"
		author = "Elastic Security"
		id = "6660d29f-aca9-4156-90a0-ce64fded281a"
		date = "2020-06-28"
		modified = "2021-08-23"
		reference = "https://www.crowdstrike.com/blog/doppelpaymer-ransomware-and-dridex-2/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Doppelpaymer.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "4c12eaa44f82c6f729e51242c9c1836eb1856959c682e2d2e21b975104c197b6"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "8bf4d098b8ce9da99a2ca13fa0759a7185ade1b3ab3b281cd15749d68546d130"
		threat_name = "Windows.Ransomware.Doppelpaymer"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "Setup run" wide fullword
		$a2 = "RtlComputeCrc32" ascii fullword

	condition:
		2 of ($a*)
}