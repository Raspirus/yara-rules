
rule ELASTIC_Windows_Virus_Floxif_493D1897 : FILE MEMORY
{
	meta:
		description = "Detects Windows Virus Floxif (Windows.Virus.Floxif)"
		author = "Elastic Security"
		id = "493d1897-864e-4f18-8511-0c6c9d990990"
		date = "2023-09-26"
		modified = "2023-11-02"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Virus_Floxif.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e628b7973ee25fdfd8f849fdf5923c6fba48141de802b0b4ce3e9ad2e40fe470"
		logic_hash = "d3f516966bd4423c49771251075a1ea2f725aec91615f7f44dd098da2a4f3574"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6a043d05ca24846cfba28b5ea603a3e512a5af4f4e15629851a922190245ca1e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 8B 54 24 04 80 7A 03 01 75 04 8D 42 04 C3 8D 42 04 53 8B C8 8A 5A 02 84 DB 74 02 30 19 8A 19 }

	condition:
		all of them
}