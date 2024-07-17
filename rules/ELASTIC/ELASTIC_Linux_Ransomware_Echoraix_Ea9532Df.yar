
rule ELASTIC_Linux_Ransomware_Echoraix_Ea9532Df : FILE MEMORY
{
	meta:
		description = "Detects Linux Ransomware Echoraix (Linux.Ransomware.EchoRaix)"
		author = "Elastic Security"
		id = "ea9532df-1136-4b11-bf4f-8838074f4e66"
		date = "2023-07-27"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Ransomware_EchoRaix.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "dfe32d97eb48fb2afc295eecfda3196cba5d27ced6217532d119a764071c6297"
		logic_hash = "4944f5a2632bfe0abebfa6f658ed3f71e4d97efcb428ed0987e2071dfd66e6a9"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "f28b340b99ec2b96ee78da50b3fc455c87dca1e898abf008c16ac192556939c5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 43 58 68 64 4B 74 7A 65 42 59 6C 48 65 58 79 5A 52 62 61 30 2F 6E 65 46 7A 34 49 7A 67 53 38 4C 68 75 36 38 5A 75 4C 4C 52 2F 66 67 6E 72 34 79 54 72 5A 54 6B 43 36 31 62 2D 59 6F 6C 49 2F 32 4C 36 66 53 55 46 52 72 55 70 49 34 6D 4E 53 41 4F 62 5F }

	condition:
		all of them
}