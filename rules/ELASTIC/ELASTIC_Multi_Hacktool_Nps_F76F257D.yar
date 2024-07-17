rule ELASTIC_Multi_Hacktool_Nps_F76F257D : FILE MEMORY
{
	meta:
		description = "Detects Multi Hacktool Nps (Multi.Hacktool.Nps)"
		author = "Elastic Security"
		id = "f76f257d-0286-4b4d-9f73-2add23cfd07e"
		date = "2024-01-24"
		modified = "2024-01-29"
		reference = "https://www.elastic.co/security-labs/unmasking-financial-services-intrusion-ref0657"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Multi_Hacktool_Nps.yar#L27-L50"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "80721b20a8667536a33fca50236f5c8e0c0d07aa7805b980e40818ab92cd9f4a"
		logic_hash = "0bbd7f86bfd2967dc390510c2e403d05e1b56551b965ea716b9e5330f75c9bd5"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "4aaa270129ce0c8fdd40aae2ebc4f6595aec91cbfea9e0188542e9c3f38eedee"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "multi"

	strings:
		$string_decrypt_add = { 0F B6 BC 34 ?? ?? ?? ?? 44 0F B6 84 34 ?? ?? ?? ?? 44 01 C7 40 88 BC 34 ?? ?? ?? ?? 48 FF C6 }
		$string_decrypt_xor = { 0F B6 54 ?? ?? 0F B6 74 ?? ?? 31 D6 40 88 74 ?? ?? 48 FF C0 }
		$string_decrypt_sub = { 0F B6 94 04 ?? ?? ?? ?? 0F B6 B4 04 ?? ?? ?? ?? 29 D6 40 88 B4 04 ?? ?? ?? ?? 48 FF C0 }
		$NewJsonDb_str0 = { 63 6C 69 65 6E 74 73 2E 6A 73 6F 6E }
		$NewJsonDb_str1 = { 68 6F 73 74 73 2E 6A 73 6F 6E }

	condition:
		all of them
}