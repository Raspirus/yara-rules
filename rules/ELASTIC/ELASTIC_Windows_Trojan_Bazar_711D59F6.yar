rule ELASTIC_Windows_Trojan_Bazar_711D59F6 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Bazar (Windows.Trojan.Bazar)"
		author = "Elastic Security"
		id = "711d59f6-6e8a-485d-b362-4c1bf1bda66e"
		date = "2021-06-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Bazar.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f29253139dab900b763ef436931213387dc92e860b9d3abb7dcd46040ac28a0e"
		logic_hash = "3bde62b468c44bdc18878fd369a7f0cf06f7be64149587a11524f725fa875f69"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a9e78b4e39f4acaba86c2595db67fcdcd40d1af611d41a023bd5d8ca9804efa4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 0F 94 C3 41 0F 95 C0 83 FA 0A 0F 9C C1 83 FA 09 0F 9F C2 31 C0 }

	condition:
		all of them
}