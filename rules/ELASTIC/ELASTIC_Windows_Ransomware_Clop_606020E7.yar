rule ELASTIC_Windows_Ransomware_Clop_606020E7 : BETA FILE MEMORY
{
	meta:
		description = "Identifies CLOP ransomware in unpacked state"
		author = "Elastic Security"
		id = "606020e7-ce1a-4a48-b801-100fd22b3791"
		date = "2020-05-03"
		modified = "2021-08-23"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.clop"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Clop.yar#L73-L92"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "f5169b324bc19f6f5a04c99f1d3326c97300d038ec383c3eab94eb258963ac30"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "5ec4e00ddf2cb1315ec7d62dd228eee0d9c15fafe4712933d42e868f83f13569"
		threat_name = "Windows.Ransomware.Clop"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$d1 = { B8 E1 83 0F 3E F7 E6 8B C6 C1 EA 04 8B CA C1 E1 05 03 CA }

	condition:
		1 of ($d*)
}