rule ELASTIC_Linux_Trojan_Xorddos_073E6161 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Xorddos (Linux.Trojan.Xorddos)"
		author = "Elastic Security"
		id = "073e6161-35a3-4e5e-a310-8cc50cb28edf"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Xorddos.yar#L457-L475"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2e06caf864595f2df7f6936bb1ccaa1e0cae325aee8659ee283b2857e6ef1e5b"
		logic_hash = "2c98058add77c55ab68491eec041d7670f726a9ec93258ae7bb8f0e6721b4ca3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "12d04597fd60ed143a1b256889eefee1f5a8c77f4f300e72743e3cfa98ba8e99"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F9 83 F8 1F 77 33 80 BC 35 B9 FF FF FF 63 76 29 8B 44 24 14 40 8D }

	condition:
		all of them
}