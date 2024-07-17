
rule ELASTIC_Linux_Trojan_Gafgyt_8D4E4F4A : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "8d4e4f4a-b3ea-4f93-ada2-2c88bb5d806d"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L1447-L1465"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "79a75c8aa5aa0d1edef5965e1bcf8ba2f2a004a77833a74870b8377d7fde89cf"
		logic_hash = "11ee101a936f8e6949701e840ef48a0fe102099ea3b71c790b9a5128e5c59029"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9601c7cf7f2b234bc30d00e1fc0217b5fa615c369e790f5ff9ca42bcd85aea12"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 50 00 FD FD 00 00 00 31 FD 48 FD FD 01 00 00 00 49 FD FD 04 }

	condition:
		all of them
}