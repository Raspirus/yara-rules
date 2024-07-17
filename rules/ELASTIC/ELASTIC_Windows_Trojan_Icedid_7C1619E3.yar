rule ELASTIC_Windows_Trojan_Icedid_7C1619E3 : FILE MEMORY
{
	meta:
		description = "IcedID Injector Variant Loader "
		author = "Elastic Security"
		id = "7c1619e3-f94a-4a46-8a81-d5dd7a58c754"
		date = "2022-12-20"
		modified = "2023-02-01"
		reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_IcedID.yar#L239-L261"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4f6de748628b8b06eeef3a5fabfe486bfd7aaa92f50dc5a8a8c70ec038cd33b1"
		logic_hash = "24ddaf474dabc5e91cce08734a035feced9048a3faac4ff236bc97e6caabd642"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ae21deaad74efaff5bec8c9010dc340118ac4c79e3bec190a7d3c3672a5a8583"
		threat_name = "Windows.Trojan.IcedID"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { C1 C9 0D 0F BE C0 03 C8 46 8A 06 84 C0 75 ?? 8B 74 24 ?? 81 F1 [4] 39 16 76 }
		$a2 = { D1 C8 F7 D0 D1 C8 2D 20 01 00 00 D1 C0 F7 D0 2D 01 91 00 00 }
		$a3 = { 8B 4E ?? FF 74 0B ?? 8B 44 0B ?? 03 C1 50 8B 44 0B ?? 03 46 ?? 50 E8 [4] 8B 46 ?? 8D 5B ?? 83 C4 0C 47 3B 78 }

	condition:
		all of them
}