rule ELASTIC_Windows_Trojan_Icedid_1Cd868A6 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Icedid (Windows.Trojan.IcedID)"
		author = "Elastic Security"
		id = "1cd868a6-d2ec-4c48-a69a-aaa6c7af876c"
		date = "2021-02-28"
		modified = "2021-08-23"
		reference = "https://www.fireeye.com/blog/threat-research/2021/02/melting-unc2198-icedid-to-ransomware-operations.html"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_IcedID.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "68dce9f214e7691db77a2f03af16a669a3cb655699f31a6c1f5aaede041468ff"
		logic_hash = "4765b2b1d463f09d7e21367c2832b3ad668aa67d8078798a14295b6e6c846c1c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3e76b3ac03c5268923cfd5d0938745d66cda273d436b83bee860250fdcca6327"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 24 2C B9 09 00 00 00 2A C2 2C 07 88 44 24 0F 0F B6 C3 6B C0 43 89 44 }

	condition:
		all of them
}