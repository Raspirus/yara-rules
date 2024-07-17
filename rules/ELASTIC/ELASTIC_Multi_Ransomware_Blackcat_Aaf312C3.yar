rule ELASTIC_Multi_Ransomware_Blackcat_Aaf312C3 : FILE MEMORY
{
	meta:
		description = "Detects Multi Ransomware Blackcat (Multi.Ransomware.BlackCat)"
		author = "Elastic Security"
		id = "aaf312c3-47b4-4dab-b7fc-8a2ac9883772"
		date = "2022-02-02"
		modified = "2023-09-20"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Multi_Ransomware_BlackCat.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0c6f444c6940a3688ffc6f8b9d5774c032e3551ebbccb64e4280ae7fc1fac479"
		logic_hash = "0771ab5a795af164a568bda036cccf08afeb33458f2cd5a7240349fca9b60ead"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "577c7f24a7ecf89a542e9a63a1744a129c96c32e8dccfbf779dd9fc6c0194930"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "multi"

	strings:
		$chacha20_enc = { EF D9 F3 0F 7F 14 3B F3 0F 7F 5C 3B 10 83 C7 20 39 F8 75 D0 8B }
		$crc32_imp = { F3 0F 6F 02 66 0F 6F D1 66 0F 3A 44 CD 11 83 C0 F0 83 C2 10 66 0F 3A 44 D4 00 83 F8 0F 66 0F EF C8 66 0F EF CA }

	condition:
		all of them
}