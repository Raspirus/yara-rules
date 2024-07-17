
rule ELASTIC_Windows_Trojan_P8Loader_E478A831 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan P8Loader (Windows.Trojan.P8Loader)"
		author = "Elastic Security"
		id = "e478a831-b2a1-4436-8b17-ca92b9581c39"
		date = "2023-04-13"
		modified = "2023-05-26"
		reference = "https://www.elastic.co/security-labs/elastic-charms-spectralviper"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_P8Loader.yar#L1-L26"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "f1a7de6bb4477ea82c18aea1ddc4481de2fc362ce5321f4205bb3b74c1c45a7e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "267743fc82c701d3029cde789eb471b49839001b21b90eeb20783382a56fb2c3"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "\t[+] Create pipe direct std success\n" fullword
		$a2 = "\tPEAddress: %p\n" fullword
		$a3 = "\tPESize: %ld\n" fullword
		$a4 = "DynamicLoad(%s, %s) %d\n" fullword
		$a5 = "LoadLibraryA(%s) FAILED in %s function, line %d" fullword
		$a6 = "\t[+] No PE loaded on memory\n" wide fullword
		$a7 = "\t[+] PE argument: %ws\n" wide fullword
		$a8 = "LoadLibraryA(%s) FAILED in %s function, line %d" fullword

	condition:
		5 of them
}