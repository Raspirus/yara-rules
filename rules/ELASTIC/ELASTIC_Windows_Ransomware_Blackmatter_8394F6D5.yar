rule ELASTIC_Windows_Ransomware_Blackmatter_8394F6D5 : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Blackmatter (Windows.Ransomware.Blackmatter)"
		author = "Elastic Security"
		id = "8394f6d5-4761-4df6-974d-eaa0a25353da"
		date = "2021-08-03"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Blackmatter.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "072158f5588440e6c94cb419ae06a27cf584afe3b0cb09c28eff0b4662c15486"
		logic_hash = "50a9b65ca6dde4fc32d2d57e72042f4380dd6c263ec5c33ce7c158151b91a5ae"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3825f59ffe9b2adc1f9dd175f4d57c9aa3dd6ff176616ecbe7c673b5b4d414f8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { FF E1 D7 66 8C 41 03 EB F8 64 E5 7E F1 06 73 AB BF 6B 1D 6A B9 B6 BA 41 A2 91 49 5E 85 51 A0 83 23 }

	condition:
		any of them
}