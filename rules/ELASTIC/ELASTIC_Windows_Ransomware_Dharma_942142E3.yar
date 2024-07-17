
rule ELASTIC_Windows_Ransomware_Dharma_942142E3 : BETA FILE MEMORY
{
	meta:
		description = "Identifies DHARMA ransomware"
		author = "Elastic Security"
		id = "942142e3-9197-41c4-86cc-66121c8a9ab5"
		date = "2020-06-25"
		modified = "2021-08-23"
		reference = "https://blog.malwarebytes.com/threat-analysis/2019/05/threat-spotlight-crysis-aka-dharma-ransomware-causing-a-crisis-for-businesses/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Dharma.yar#L67-L86"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "af5068ef3442964e4d1c5e27090fb84eaf762ff23463b7a0c2902e523ae601c1"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "e8ee60d53f92dd1ade8cc956c13a5de38f9be9050131ba727f2fab41dde619a8"
		threat_name = "Windows.Ransomware.Dharma"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "C:\\crysis\\Release\\PDB\\payload.pdb" ascii fullword

	condition:
		1 of ($a*)
}