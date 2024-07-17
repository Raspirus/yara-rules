
rule ELASTIC_Windows_Ransomware_Haron_23B76Cb7 : FILE MEMORY
{
	meta:
		description = "Direct overlap with Thanos/Avaddon"
		author = "Elastic Security"
		id = "23b76cb7-6f96-4012-ad66-2e4e4ae744a9"
		date = "2021-08-03"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Haron.yar#L22-L41"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6e6b78a1df17d6718daa857827a2a364b7627d9bfd6672406ad72b276014209c"
		logic_hash = "e53c92be617444da0057680ee1ac45cbc1f707194281644bececa44e4ebe3580"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9dc91a56ef17873f3e833d85fa947facde741d80a574ae911261e553a40a2731"
		threat_name = "Windows.Ransomware.Haron"
		severity = 90
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 0A 28 06 00 00 06 26 DE 0A 08 2C 06 08 6F 48 00 00 0A DC DE }

	condition:
		any of them
}