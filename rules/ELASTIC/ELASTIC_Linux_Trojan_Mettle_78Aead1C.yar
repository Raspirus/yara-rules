
rule ELASTIC_Linux_Trojan_Mettle_78Aead1C : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mettle (Linux.Trojan.Mettle)"
		author = "Elastic Security"
		id = "78aead1c-7dc2-4db0-a0b8-cccf2d583c67"
		date = "2024-05-06"
		modified = "2024-05-21"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mettle.yar#L54-L81"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "864eae4f27648b8a9d9b0eb1894169aa739311cdd02b1435a34881acf7059d58"
		logic_hash = "d68d37379b8a3a2d242030fd14884781488e9785823aa25fedfdd406748f8039"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "bf2b8bd0e12905ab4bed94c70dbd854a482446909ba255fceaee309efd69b835"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$process_set_nonblocking_stdio = { 48 83 EC 08 31 D2 BE 03 00 00 00 31 FF 31 C0 E8 ?? ?? ?? ?? 80 CC 08 BE 04 00 00 00 31 FF 89 C2 31 C0 E8 ?? ?? ?? ?? 31 D2 BE 03 00 00 00 BF 01 00 00 00 31 C0 E8 ?? ?? ?? ?? 80 CC 08 BE 04 00 00 00 BF 01 00 00 00 89 C2 31 C0 E8 }
		$process_create = { 41 57 41 56 49 89 CE 41 55 41 54 4D 89 C5 55 53 48 89 FB 48 89 D5 48 81 EC 88 00 00 00 48 8D ?? ?? ?? 48 89 34 24 E8 ?? ?? ?? ?? FF C0 0F ?? ?? ?? ?? ?? BE 20 01 00 00 BF 01 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 49 89 C7 0F ?? ?? ?? ?? ?? 41 F6 45 28 80 74 ?? 48 8D ?? ?? ?? 31 C9 31 D2 31 F6 E8 ?? ?? ?? ?? 85 C0 }
		$process_read = { 48 85 FF 74 ?? 41 55 41 54 49 89 FD 55 53 48 89 D5 49 89 F4 48 83 EC 08 48 8B 7F 38 E8 ?? ?? ?? ?? 48 39 C5 48 89 C3 76 ?? 49 8B 7D 70 48 89 EA 49 8D ?? ?? 48 29 C2 E8 ?? ?? ?? ?? 48 01 C3 5A 48 89 D8 5B 5D 41 5C 41 5D C3 }
		$file_new = { 41 54 55 48 89 F5 53 48 89 FB 48 8B 7F 10 BE B2 04 01 00 E8 ?? ?? ?? ?? 48 8B 7B 10 BE B3 04 01 00 49 89 C4 E8 ?? ?? ?? ?? 48 85 C0 75 ?? 48 8D ?? ?? ?? ?? ?? 48 89 C6 4C 89 E7 E8 ?? ?? ?? ?? 83 CA FF 48 85 C0 74 ?? 48 89 C6 48 89 EF E8 ?? ?? ?? ?? 31 D2 5B 89 D0 5D 41 5C C3 }
		$file_read = { 53 48 89 F3 48 83 EC 10 48 89 54 24 08 E8 ?? ?? ?? ?? 48 8B 54 24 08 48 83 C4 10 48 89 DF 5B 48 89 C1 BE 01 00 00 00 E9 }
		$file_seek = { 48 83 EC 18 48 89 74 24 08 89 54 24 04 E8 ?? ?? ?? ?? 8B 54 24 04 48 8B 74 24 08 48 89 C7 48 83 C4 18 E9 }
		$func_write_audio_file = { 41 54 55 49 89 F4 53 48 89 D3 E8 ?? ?? ?? ?? 48 8B 30 48 8B 78 08 48 89 C5 48 01 DE 48 89 30 E8 ?? ?? ?? ?? 48 89 C7 48 89 45 08 48 83 C8 FF 48 85 FF 74 ?? 48 8B 45 00 48 29 DF 4C 89 E6 48 89 D9 48 01 F8 48 89 C7 48 89 D8 F3 ?? 5B 5D 41 5C C3 }
		$func_is_compatible_elf = { 31 C0 81 3F 7F 45 4C 46 75 ?? 80 7F 04 02 75 ?? 53 0F B6 5F 05 BF 01 00 00 00 E8 ?? ?? ?? ?? FF C8 0F 94 C0 0F B6 C0 FF C0 39 C3 0F 94 C0 0F B6 C0 83 E0 01 5B C3 83 E0 01 C3 }
		$func_stack_setup = { 48 89 EA 31 C0 49 8B 0C C0 48 FF C0 48 85 C9 74 ?? 48 89 0A 48 83 C2 08 EB ?? 48 C7 02 00 00 00 00 48 C7 44 C5 00 00 00 00 00 EB ?? 48 89 EF 4C 89 4C 24 08 E8 ?? ?? ?? ?? 4C 8B 4C 24 08 48 83 C4 10 48 89 DA 48 89 EF 5B 5D 41 5C 4C 89 CE }
		$func_c2_new_struct = { 48 89 DF 48 C7 43 20 00 00 00 00 C7 43 28 00 00 00 00 48 C7 43 40 00 00 00 00 48 89 43 38 48 8B 05 D1 BE 09 00 48 89 5B 30 48 89 43 48 E8 }

	condition:
		2 of ($process*) and 2 of ($file*) and 2 of ($func*)
}