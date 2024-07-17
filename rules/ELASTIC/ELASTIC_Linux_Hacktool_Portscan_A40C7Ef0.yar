rule ELASTIC_Linux_Hacktool_Portscan_A40C7Ef0 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Portscan (Linux.Hacktool.Portscan)"
		author = "Elastic Security"
		id = "a40c7ef0-627c-4965-b4d3-b05b79586170"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Portscan.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c389c42bac5d4261dbca50c848f22c701df4c9a2c5877dc01e2eaa81300bdc29"
		logic_hash = "6118ea86d628450e79ee658f4b95bae40080764a25240698d8ca7fcb7e6adaaf"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "bf686c3c313936a144265cbf75850c8aee3af3ae36cb571050c7fceed385451d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 54 50 44 00 52 65 73 70 6F 6E 73 65 20 77 61 73 20 4E 54 50 20 }

	condition:
		all of them
}