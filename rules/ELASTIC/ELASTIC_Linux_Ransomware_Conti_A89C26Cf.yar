
rule ELASTIC_Linux_Ransomware_Conti_A89C26Cf : FILE MEMORY
{
	meta:
		description = "Detects Linux Ransomware Conti (Linux.Ransomware.Conti)"
		author = "Elastic Security"
		id = "a89c26cf-ccec-40ca-85d3-d014b767fd6a"
		date = "2023-07-30"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Ransomware_Conti.yar#L21-L42"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "95776f31cbcac08eb3f3e9235d07513a6d7a6bf9f1b7f3d400b2cf0afdb088a7"
		logic_hash = "301f3f3ece06a1cd6788db6e3003497b27470780eaaad95f40ed926e7623793e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c29bb1bbbd76712bbc3ddd1dfeeec40b230677339dea7441b1f34159ccbbdf9f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = "paremeter --size cannot be %d" fullword
		$a2 = "--vmkiller" fullword
		$a3 = ".conti" fullword
		$a4 = "Cannot create file vm-list.txt" fullword

	condition:
		3 of them
}