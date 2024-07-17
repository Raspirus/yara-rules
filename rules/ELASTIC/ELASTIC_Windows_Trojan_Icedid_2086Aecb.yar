rule ELASTIC_Windows_Trojan_Icedid_2086Aecb : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Icedid (Windows.Trojan.IcedID)"
		author = "Elastic Security"
		id = "2086aecb-161b-4102-89c7-580fb9ac3759"
		date = "2022-04-06"
		modified = "2022-03-02"
		reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_IcedID.yar#L165-L184"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b9fb0a4c28613c556fb67a0b0e7c9d4c1236b60a161ad935e7387aec5911413a"
		logic_hash = "561bf7eacfbbf1b4e0c111347f0d6ff4325bdbce8db73bee1ba836b610569c0d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a8b6cbb3140ff3e1105bb32a2da67831917caccc4985c485bbfdb0aa50016d86"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 4C 8D 05 [4] 42 8A 44 01 ?? 42 32 04 01 88 44 0D ?? 48 FF C1 48 83 F9 20 72 ?? }

	condition:
		all of them
}