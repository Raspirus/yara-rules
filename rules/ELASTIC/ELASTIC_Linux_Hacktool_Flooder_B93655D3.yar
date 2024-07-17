
rule ELASTIC_Linux_Hacktool_Flooder_B93655D3 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "b93655d3-1d3f-42f4-a47f-a69624e90da5"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L81-L98"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "34cb06385543c6c2c562f757df2f641d8402e7c9f95fa924e17652a1c38d695f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "55119467cb5f9789b74064e63c1e7d905457b54f6e4da1a83c498313d6c90b5b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C0 49 89 C5 74 45 45 85 F6 7E 28 48 89 C3 41 8D 46 FF 4D 8D 64 }

	condition:
		all of them
}