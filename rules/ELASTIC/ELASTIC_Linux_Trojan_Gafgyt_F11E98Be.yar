rule ELASTIC_Linux_Trojan_Gafgyt_F11E98Be : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "f11e98be-bf81-480e-b2d1-dcc748c6869d"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L1427-L1445"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "79a75c8aa5aa0d1edef5965e1bcf8ba2f2a004a77833a74870b8377d7fde89cf"
		logic_hash = "9b9122f0897610dff6b37446b3cecbfcec3dce8dc7e1934e78cc32d5f6ac9648"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8cdf2acffd0cdce48ceaffa6682d2f505c557b873e4f418f4712dfa281a3095a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { FD 40 00 09 FD 21 FD FD 08 48 FD 80 3E 00 75 FD FD 4C 24 48 0F FD }

	condition:
		all of them
}