rule ELASTIC_Windows_Trojan_Naplistener_E8F16920 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Naplistener (Windows.Trojan.NapListener)"
		author = "Elastic Security"
		id = "e8f16920-52ca-46b6-a945-1b919f975aae"
		date = "2023-02-28"
		modified = "2023-03-20"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_NapListener.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6e8c5bb2dfc90bca380c6f42af7458c8b8af40b7be95fab91e7c67b0dee664c4"
		logic_hash = "6cb7b5051fab2b56f39b2805788b5b0838a095b41fcc623fe412b215736be5d4"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "36689095792e7eb7fce23e7d390675a3554c8a5ba4356aaf9c2fa8986d3a0439"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$start_routine = { 02 28 08 00 00 0A 00 00 28 03 00 00 0A 0A 14 FE 06 04 00 00 06 73 04 00 00 0A 73 05 00 00 0A 0B 16 28 06 00 00 0A 00 07 06 6F 07 00 00 0A 00 00 2A }
		$main_routine = { 6F 22 00 00 0A 13 0E 11 0D 1F 24 14 16 8D 16 00 00 01 14 6F 23 00 00 0A 13 0F 11 0F 14 6F 24 00 00 0A 13 10 11 0E 11 10 18 8D 01 00 00 01 }
		$start_thread = { 00 28 03 00 00 0A 0A 14 FE 06 04 00 00 06 73 04 00 00 0A 73 05 00 00 0A 0B 16 28 06 00 00 0A 00 07 06 6F 07 00 00 0A 00 2A }

	condition:
		2 of them
}