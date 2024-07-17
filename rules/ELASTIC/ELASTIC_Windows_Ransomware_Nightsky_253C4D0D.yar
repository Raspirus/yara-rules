
rule ELASTIC_Windows_Ransomware_Nightsky_253C4D0D : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Nightsky (Windows.Ransomware.Nightsky)"
		author = "Elastic Security"
		id = "253c4d0d-157f-4929-9f0e-5830ebc377dc"
		date = "2022-03-14"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Nightsky.yar#L24-L42"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2c940a35025dd3847f7c954a282f65e9c2312d2ada28686f9d1dc73d1c500224"
		logic_hash = "ba9e6dab664e464e0fdc65bd8bdccc661846d85e7fd8fbf089e72e9e5b71fb17"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "739529dfb1f8c8ab2a7f6a4b2b18b27dd2fcc38eda0f110897fc6cb5d64b1c92"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 43 B8 48 2B D9 49 89 43 C0 4C 8B E2 49 89 43 C8 4C 8B F1 49 89 }

	condition:
		all of them
}