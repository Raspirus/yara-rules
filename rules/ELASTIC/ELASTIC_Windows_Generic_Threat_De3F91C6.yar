rule ELASTIC_Windows_Generic_Threat_De3F91C6 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "de3f91c6-bca8-4ed6-8ba3-a53903556903"
		date = "2024-01-31"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2355-L2373"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e2cd4a8ccbf4a3a93c1387c66d94e9506b5981357004929ce5a41fcedfffb20f"
		logic_hash = "032ac2adb11782d823f50bfedf4e4decb731dbe7d3abbb3b05ccff598ba7edb8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "bd994a85b967e56628a3fcd784e4d73cf6bd9f34a222d1bb52b1e87b775fdd06"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 56 8B 75 08 80 7E 04 00 74 08 FF 36 E8 0B 41 00 00 59 83 26 00 C6 46 04 00 5E 5D C3 55 8B EC 8B 45 08 8B 4D 0C 3B C1 75 04 33 C0 5D C3 83 C1 05 83 C0 05 8A 10 3A 11 75 18 84 D2 74 EC }

	condition:
		all of them
}