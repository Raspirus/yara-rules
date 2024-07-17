rule ELASTIC_Windows_Ransomware_Ryuk_1A4Ad952 : BETA FILE MEMORY
{
	meta:
		description = "Identifies RYUK ransomware"
		author = "Elastic Security"
		id = "1a4ad952-cc99-4653-932b-290381e7c871"
		date = "2020-04-30"
		modified = "2021-08-23"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Ryuk.yar#L69-L88"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "bb854f5760f41e2c103c99d8f128a2546926a614dff8753eaa1287ac583e213a"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "d8c5162850e758e27439e808e914df63f42756c0b8f7c2b5f9346c0731d3960c"
		threat_name = "Windows.Ransomware.Ryuk"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$e1 = { 8B 0A 41 8D 45 01 45 03 C1 48 8D 52 08 41 3B C9 41 0F 45 C5 44 8B E8 49 63 C0 48 3B C3 72 E1 }

	condition:
		1 of ($e*)
}