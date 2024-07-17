rule ELASTIC_Windows_Ransomware_Ryuk_25D3C5Ba : BETA FILE MEMORY
{
	meta:
		description = "Identifies RYUK ransomware"
		author = "Elastic Security"
		id = "25d3c5ba-8f80-4af0-8a5d-29c974fb016a"
		date = "2020-04-30"
		modified = "2021-08-23"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Ryuk.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "4d461ff9b87e3a17637cef89ff8a85ef22f69695d4664f6fe8f271a6a5f7b4bc"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "18e70599e3a187e77697844fa358dd150e7e25ac74060e8c7cf2707fb7304efd"
		threat_name = "Windows.Ransomware.Ryuk"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$g1 = { 41 8B C0 45 03 C7 99 F7 FE 48 63 C2 8A 4C 84 20 }

	condition:
		1 of ($g*)
}