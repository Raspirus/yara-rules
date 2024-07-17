rule ELASTIC_Windows_Trojan_Qbot_3074A8D4 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Qbot (Windows.Trojan.Qbot)"
		author = "Elastic Security"
		id = "3074a8d4-d93c-4987-9031-9ecd3881730d"
		date = "2022-06-07"
		modified = "2022-07-18"
		reference = "https://www.elastic.co/security-labs/exploring-the-qbot-attack-pattern"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Qbot.yar#L66-L97"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c2ba065654f13612ae63bca7f972ea91c6fe97291caeaaa3a28a180fb1912b3a"
		logic_hash = "90c06bd09fe640bb5a6be8e4f2384fb15c7501674d57db005e790ed336740c99"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c233a0c24576450ce286d96126379b6b28d537619e853d860e2812f521b810ac"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "qbot" wide
		$a2 = "stager_1.obf\\Benign\\mfc" wide
		$a3 = "common.obf\\Benign\\mfc" wide
		$a4 = "%u;%u;%u;"
		$a5 = "%u.%u.%u.%u.%u.%u.%04x"
		$a6 = "%u&%s&%u"
		$get_string1 = { 33 D2 8B ?? 6A 5A 5? F7 ?? 8B ?? 08 8A 04 ?? 8B 55 ?? 8B ?? 10 3A 04 ?? }
		$get_string2 = { 33 D2 8B ?? F7 75 F4 8B 45 08 8A 04 02 32 04 ?? 88 04 ?? ?? 83 ?? 01 }
		$set_key = { 8D 87 00 04 00 00 50 56 E8 ?? ?? ?? ?? 59 8B D0 8B CE E8 }
		$do_computer_use_russian_like_keyboard = { B9 FF 03 00 00 66 23 C1 33 C9 0F B7 F8 66 3B 7C 4D }
		$execute_each_tasks = { 8B 44 0E ?? 85 C0 74 ?? FF D0 EB ?? 6A 00 6A 00 6A 00 FF 74 0E ?? E8 ?? ?? ?? ?? 83 C4 10 }
		$generate_random_alpha_num_string = { 57 E8 ?? ?? ?? ?? 48 50 8D 85 ?? ?? ?? ?? 6A 00 50 E8 ?? ?? ?? ?? 8B 4D ?? 83 C4 10 8A 04 38 88 04 0E 46 83 FE 0C }
		$load_base64_dll_from_file_and_inject_into_targets = { 10 C7 45 F0 50 00 00 00 83 65 E8 00 83 7D F0 0B 73 08 8B 45 F0 89 }

	condition:
		6 of them
}