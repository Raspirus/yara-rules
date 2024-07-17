rule ELASTIC_Windows_Trojan_Nighthawk_23489175 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Nighthawk (Windows.Trojan.Nighthawk)"
		author = "Elastic Security"
		id = "23489175-ed41-4f43-ac85-b9ae3ffb55d9"
		date = "2023-06-14"
		modified = "2023-07-10"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Nighthawk.yar#L49-L74"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "697742d5dd071add40b700022fd30424cb231ffde223d21bd83a44890e06762f"
		logic_hash = "be41fc53f7098ca3cf718e8066a488196423ede993466c9a24ad2af387e03b24"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3ff9fe5ef10afa328025a6abd509af788a9b1d5ef73a379e3767b2a4291566a3"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$pdb = "C:\\Users\\Peter\\Desktop\\dev\\implant\\CommsChannel\\x64\\Release-ReflectiveDLL\\Implant.x64.pdb" ascii fullword
		$seq_str_decrypt = { 48 8B C3 48 83 7B ?? ?? 72 ?? 48 8B 03 0F BE 14 06 49 8B CF E8 ?? ?? ?? ?? 48 85 C0 74 ?? 49 2B C7 48 8D 0D ?? ?? ?? ?? 8A 0C 08 48 8B C3 48 83 7B ?? ?? 72 ?? 48 8B 03 88 0C 06 }
		$seq_hvnc = { BA 06 01 00 00 41 B9 00 00 20 A0 41 B8 20 00 00 00 48 8B CE FF 15 }
		$seq_pe_parsing = { 8B 44 24 ?? 48 6B C0 28 48 8B 4C 24 ?? 8B 44 01 ?? 48 8B 8C 24 ?? ?? ?? ?? 48 03 C8 48 8B C1 48 89 44 24 ?? 8B 44 24 ?? 48 6B C0 28 48 8B 4C 24 ?? 8B 44 01 ?? 89 44 24 ?? EB ?? }
		$seq_library_resolver = { 48 8B 84 24 ?? ?? ?? ?? 48 89 44 24 ?? 48 8B 44 24 ?? 48 63 40 ?? 48 8B 4C 24 ?? 48 03 C8 48 8B C1 48 89 44 24 ?? B8 ?? ?? ?? ?? 48 6B C0 ?? 48 8B 4C 24 ?? 8B 84 01 ?? ?? ?? ?? 89 44 24 ?? 83 7C 24 ?? ?? 75 ?? 33 C0 E9 ?? ?? ?? ?? }
		$seq_disk_info = { 4C 8B A3 B0 00 00 00 48 8B BB A8 00 00 00 49 3B FC 0F 84 ?? ?? ?? ?? 48 8D B3 D8 00 00 00 4C 8D B3 F0 00 00 00 4C 8D BB C0 00 00 00 45 33 ED }
		$seq_keyname = { 8B 4B 08 C1 E1 08 0B 4B 04 C1 E1 10 41 B8 40 00 00 00 48 8D 95 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }
		$seq_tcptable = { 41 BF 02 00 00 00 41 3B FF 74 ?? 83 FF 17 41 8B C7 75 ?? B8 08 00 00 00 }

	condition:
		(1 of ($pdb)) or (2 of ($seq*))
}