
rule ELASTIC_Linux_Trojan_Mettle_813B9B6C : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mettle (Linux.Trojan.Mettle)"
		author = "Elastic Security"
		id = "813b9b6c-946d-46f0-a255-d06ab78347d4"
		date = "2024-05-06"
		modified = "2024-05-21"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mettle.yar#L25-L52"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "bb651d974ca3f349858db7b5a86f03a8d47d668294f27e709a823fa11e6963d7"
		logic_hash = "a6a9cf424bf1ca7985e1c4b14123ed236208ffa3f7c9ffebbdd85765a90bfa54"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6b350abfda820ee4c6e7aa84f732ab4527c454b93ae13363747f024bb8c5e3b4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$process_set_nonblocking_stdio = { 55 89 E5 53 83 EC 08 E8 ?? ?? ?? ?? 81 C3 3D 32 0D 00 6A 00 6A 03 6A 00 E8 ?? ?? ?? ?? 83 C4 0C 80 CC 08 50 6A 04 6A 00 E8 ?? ?? ?? ?? 83 C4 0C 6A 00 6A 03 6A 01 E8 ?? ?? ?? ?? 83 C4 0C 80 CC 08 50 6A 04 6A 01 E8 }
		$process_create = { 55 89 E5 57 56 53 81 EC 98 00 00 00 E8 ?? ?? ?? ?? 81 C3 A6 3B 0D 00 89 45 84 89 95 78 FF FF FF 89 4D 80 8B 7D 0C 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 10 40 0F ?? ?? ?? ?? ?? 50 50 68 B4 00 00 00 6A 01 E8 ?? ?? ?? ?? 89 C6 83 C4 10 85 C0 0F ?? ?? ?? ?? ?? F6 47 14 80 74 ?? 6A 00 6A 00 6A 00 8D 45 ?? 50 E8 ?? ?? ?? ?? 89 85 7C FF FF FF }
		$process_read = { 55 89 E5 57 56 53 83 EC 1C E8 ?? ?? ?? ?? 81 C3 90 30 0D 00 8B 4D 08 8B 7D 0C 8B 75 10 83 C8 FF 85 C9 74 ?? 52 56 57 FF 71 24 89 4D E4 E8 ?? ?? ?? ?? 89 C2 83 C4 10 39 C6 8B 4D E4 76 ?? 50 29 D6 56 01 D7 89 55 E4 57 FF 71 48 E8 ?? ?? ?? ?? 8B 55 E4 01 C2 83 C4 10 89 D0 8D 65 ?? 5B 5E 5F 5D C3 }
		$file_new = { 83 C4 10 52 52 50 FF 76 0C E8 ?? ?? ?? ?? 89 34 24 E8 ?? ?? ?? ?? 83 C4 10 8D 65 ?? 5B 5E 5F 5D C3 }
		$file_read = { 55 89 E5 53 83 EC 10 E8 ?? ?? ?? ?? 81 C3 41 A7 0D 00 FF 75 08 E8 ?? ?? ?? ?? 50 FF 75 10 6A 01 FF 75 0C E8 ?? ?? ?? ?? 8B 5D FC C9 C3 }
		$file_seek = { 55 89 E5 53 83 EC 10 E8 ?? ?? ?? ?? 81 C3 C0 A6 0D 00 FF 75 08 E8 ?? ?? ?? ?? 83 C4 0C FF 75 10 FF 75 0C 50 E8 ?? ?? ?? ?? 8B 5D FC C9 C3 }
		$func_write_audio_file = { 55 89 E5 57 56 53 83 EC 18 E8 ?? ?? ?? ?? 81 C3 D8 23 0D 00 FF 75 08 E8 ?? ?? ?? ?? 89 C6 8B 45 10 03 06 89 06 5A 59 50 FF 76 04 E8 ?? ?? ?? ?? 89 C7 89 46 04 83 C4 10 83 C8 FF 85 FF 74 ?? 2B 7D 10 8B 06 01 F8 89 C7 8B 75 0C 8B 4D 10 F3 ?? 8B 45 10 8D 65 ?? 5B 5E 5F 5D C3 }
		$func_is_compatible_elf = { 55 89 E5 56 53 E8 ?? ?? ?? ?? 81 C3 CF AB 05 00 8B 55 08 31 C0 81 3A 7F 45 4C 46 75 ?? 80 7A 04 01 75 ?? 0F B6 72 05 83 EC 0C 6A 01 E8 ?? ?? ?? ?? 83 C4 10 48 0F 94 C0 0F B6 C0 40 39 C6 0F 94 C0 0F B6 C0 83 E0 01 8D 65 ?? 5B 5E 5D C3 }
		$func_stack_setup = { 89 DA 31 C0 8B 0C 86 85 C9 8D 40 ?? 74 ?? 89 0A 83 C2 04 EB ?? C7 02 00 00 00 00 C7 04 83 00 00 00 00 EB ?? 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 8B 45 DC 89 45 10 8B 45 E0 89 45 0C 89 5D 08 8D 65 ?? 5B 5E 5F 5D }
		$func_c2_new_struct = { C7 46 14 00 00 00 00 C7 46 10 00 00 00 00 C7 46 18 00 00 00 00 8D 83 ?? ?? ?? ?? 89 46 20 C7 46 24 00 00 00 00 C7 46 28 00 00 00 00 C7 46 2C 00 00 00 00 C7 46 30 00 00 F0 3F 89 76 1C 83 EC 0C 56 E8 }

	condition:
		2 of ($process*) and 2 of ($file*) and 2 of ($func*)
}