rule ELASTIC_Windows_Ransomware_Dharma_E9319E4A : BETA FILE MEMORY
{
	meta:
		description = "Identifies DHARMA ransomware"
		author = "Elastic Security"
		id = "e9319e4a-3850-4bad-9579-4b73199a0963"
		date = "2020-06-25"
		modified = "2021-08-23"
		reference = "https://blog.malwarebytes.com/threat-analysis/2019/05/threat-spotlight-crysis-aka-dharma-ransomware-causing-a-crisis-for-businesses/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Dharma.yar#L46-L65"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "182ed508d645a0b1fab80fb6f975a05d33b64c43005bd3656df6470934cd71f4"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "4a4f3aebe4c9726cf62dde454f01cbf6dcb09bf3ef1b230d548fe255f01254aa"
		threat_name = "Windows.Ransomware.Dharma"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$d = { 08 8B 51 24 8B 45 08 8B 48 18 0F B7 14 51 85 D2 74 47 8B 45 08 8B }

	condition:
		1 of ($d*)
}