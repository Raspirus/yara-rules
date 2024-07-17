rule ELASTIC_Windows_Generic_Threat_D7B57912 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "d7b57912-02b4-421a-8f93-9e8371314e68"
		date = "2024-05-23"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L3465-L3483"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0906599be152dd598c7f540498c44cc38efe9ea976731da05137ee6520288fe4"
		logic_hash = "a774e3030d81e29805a9784cfbbc0b69c4fedebe0daa25e403777e1f46f9094f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "36a3fecc918cd891d9c779f7ff54019908ba190853739c8059adb84233643a1c"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 83 C4 B8 53 56 8B DA 89 45 FC 8D 45 FC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 64 FF 30 64 89 20 8B C3 ?? ?? ?? ?? ?? 6A 00 6A 00 8D 45 F0 50 8B 45 FC }

	condition:
		all of them
}