
rule ELASTIC_Windows_Generic_Threat_Fca7F863 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "fca7f863-8d5b-4b94-8f60-a72c76782d1d"
		date = "2024-01-29"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2294-L2312"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9d0e786dd8f1dc05eae910c6bcf15b5d05b4b6b0543618ca0c2ff3c4bb657af3"
		logic_hash = "ad45fe6e8257d012824b36aaee1beccb82c1b78031de86c1f1dd26d5be88aa6f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4b391399465f18b01d7cbdf222dd7249f4fff0a5b4b931e568d92f47cc283a27"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 89 E5 8D 64 24 F4 53 89 C3 6A 0C 8D 45 F4 50 6A 00 FF 53 10 50 FF 53 0C 50 FF 53 24 8B 45 F4 89 43 2C 03 40 3C 8B 40 50 89 43 34 6A 40 68 00 30 00 00 FF 73 34 6A 00 FF 13 89 43 30 8B 4B 34 }

	condition:
		all of them
}