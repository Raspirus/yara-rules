rule ELASTIC_Linux_Hacktool_Lightning_D9A9173A : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Lightning (Linux.Hacktool.Lightning)"
		author = "Elastic Security"
		id = "d9a9173a-6372-4892-8913-77f5749aa045"
		date = "2022-11-08"
		modified = "2024-02-13"
		reference = "https://www.intezer.com/blog/research/lightning-framework-new-linux-threat/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Lightning.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "48f9471c20316b295704e6f8feb2196dd619799edec5835734fc24051f45c5b7"
		logic_hash = "93961d9771aa4e828e15923064a848291c7814ad4e15e30cd252fc41523d789e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f6e9d662f22b6f08c5e6d32994d6ed933c6863870352dfb76e1540676663e7e0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = "cat /sys/class/net/%s/address" ascii fullword
		$a2 = "{\"ComputerName\":\"%s\",\"Guid\":\"%s\",\"RequestName\":\"%s\",\"Licence\":\"%s\"}" ascii fullword
		$a3 = "sleep 60 && ./%s &" ascii fullword
		$a4 = "Lightning.Core" ascii fullword

	condition:
		all of them
}