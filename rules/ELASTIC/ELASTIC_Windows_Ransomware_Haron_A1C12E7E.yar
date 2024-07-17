rule ELASTIC_Windows_Ransomware_Haron_A1C12E7E : FILE MEMORY
{
	meta:
		description = "Direct overlap with Thanos/Avaddon"
		author = "Elastic Security"
		id = "a1c12e7e-a740-4d26-a0ed-310a2b03fe50"
		date = "2021-08-03"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Haron.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6e6b78a1df17d6718daa857827a2a364b7627d9bfd6672406ad72b276014209c"
		logic_hash = "84df5a13495acee5dc2007cf1d6e1828a832d46fcbad2ca8676643fd47756248"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c6abe96bd2848bb489f856373356dbad3fca273e9d71394ec22960070557ad11"
		threat_name = "Windows.Ransomware.Haron"
		severity = 90
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 00 04 28 0E 00 00 0A 06 FE 06 2A 00 00 06 73 0F 00 00 0A 28 }

	condition:
		any of them
}