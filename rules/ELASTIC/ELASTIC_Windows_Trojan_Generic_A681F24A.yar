
rule ELASTIC_Windows_Trojan_Generic_A681F24A : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Generic (Windows.Trojan.Generic)"
		author = "Elastic Security"
		id = "a681f24a-7054-4525-bcf8-3ee64a1d8413"
		date = "2021-06-10"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Generic.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a796f316b1ed7fa809d9ad5e9b25bd780db76001345ea83f5035a33618f927fa"
		logic_hash = "72bfefc8f92dbe65d197e02bf896315dcbc54d7b68d0434f43de026ccf934f40"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "6323ed5b60e728297de19c878cd96b429bfd6d82157b4cf3475f3a3123921ae0"
		severity = 25
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = "_kasssperskdy" wide fullword
		$b = "[Time:]%d-%d-%d %d:%d:%d" wide fullword
		$c = "{SDTB8HQ9-96HV-S78H-Z3GI-J7UCTY784HHC}" wide fullword

	condition:
		2 of them
}