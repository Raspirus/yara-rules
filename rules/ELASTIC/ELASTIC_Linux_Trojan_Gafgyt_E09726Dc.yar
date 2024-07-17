rule ELASTIC_Linux_Trojan_Gafgyt_E09726Dc : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "e09726dc-4e6d-4115-b178-d20375c09e04"
		date = "2022-01-05"
		modified = "2022-01-26"
		reference = "1e64187b5e3b5fe71d34ea555ff31961404adad83f8e0bd1ce0aad056a878d73"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L1327-L1345"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "ebd00e593a7fcd46e36fd0ca213e1f82c0f4a94448b6fd605d35cea45a490493"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "614d54b3346835cd5c2a36a54cae917299b1a1ae0d057e3fa1bb7dddefc1490f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 00 48 83 EC 08 48 83 C4 08 C3 00 00 00 01 00 02 00 50 49 4E 47 }

	condition:
		all of them
}