rule ELASTIC_Linux_Ransomware_Akira_02237952 : FILE MEMORY
{
	meta:
		description = "Detects Linux Ransomware Akira (Linux.Ransomware.Akira)"
		author = "Elastic Security"
		id = "02237952-b9ac-44e5-a32f-f3cc8f28a89b"
		date = "2023-07-28"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Ransomware_Akira.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1d3b5c650533d13c81e325972a912e3ff8776e36e18bca966dae50735f8ab296"
		logic_hash = "a9b3cdddb3387251d7da90f32b08b9c1eedcdff1fe90d51f4732183666a6d467"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7fcfac47be082441f6df149d0615a9d2020ac1e9023eabfcf10db4fe400cd474"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = "No path to encrypt" fullword
		$a2 = "--encryption_percent" fullword
		$a3 = "Failed to import public key" fullword
		$a4 = "akira_readme.txt" fullword

	condition:
		3 of them
}