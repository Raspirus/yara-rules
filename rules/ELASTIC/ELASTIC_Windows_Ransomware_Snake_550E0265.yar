
rule ELASTIC_Windows_Ransomware_Snake_550E0265 : BETA FILE MEMORY
{
	meta:
		description = "Identifies SNAKE ransomware"
		author = "Elastic Security"
		id = "550e0265-fca9-46df-9d5a-cf3ef7efc7ff"
		date = "2020-06-30"
		modified = "2021-08-23"
		reference = "https://labs.sentinelone.com/new-snake-ransomware-adds-itself-to-the-increasing-collection-of-golang-crimeware/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Snake.yar#L1-L24"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "d9c2f6961a4ef560743060ed176bdc606561ca1b8270b8826cb0dbadaf4e5dbc"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "f2796560ddc85ad98a5ef4f0d7323948d57116813c8a26ab902fdfde849704e0"
		threat_name = "Windows.Ransomware.Snake"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "Go build ID: \"X6lNEpDhc_qgQl56x4du/fgVJOqLlPCCIekQhFnHL/rkxe6tXCg56Ez88otHrz/Y-lXW-OhiIbzg3-ioGRz\"" ascii fullword
		$a2 = "We breached your corporate network and encrypted the data on your computers."
		$a3 = "c:\\users\\public\\desktop\\Fix-Your-Files.txt" nocase
		$a4 = "%System Root%\\Fix-Your-Files.txt" nocase
		$a5 = "%Desktop%\\Fix-Your-Files.txt" nocase

	condition:
		1 of ($a*)
}