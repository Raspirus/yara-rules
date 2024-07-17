
rule ELASTIC_Windows_Ransomware_Lockbit_89E64044 : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Lockbit (Windows.Ransomware.Lockbit)"
		author = "Elastic Security"
		id = "89e64044-74e4-4679-b6ad-bfb9b264330c"
		date = "2021-08-06"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Lockbit.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0d6524b9a1d709ecd9f19f75fa78d94096e039b3d4592d13e8dbddf99867182d"
		logic_hash = "bd504b078704b9f307a50c8556c143eee061015a9727670137aadc47ae93e2a6"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ec45013d3ecbc39ffce5ac18d5bf8b0d18bcadd66659975b0a9f26bcae0a5b49"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "\\LockBit_Ransomware.hta" wide fullword
		$a2 = "\\Registry\\Machine\\Software\\Classes\\Lockbit\\shell" wide fullword
		$a3 = "%s\\%02X%02X%02X%02X.lock" wide fullword

	condition:
		all of them
}