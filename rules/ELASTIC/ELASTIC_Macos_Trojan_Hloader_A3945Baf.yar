
rule ELASTIC_Macos_Trojan_Hloader_A3945Baf : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Hloader (MacOS.Trojan.HLoader)"
		author = "Elastic Security"
		id = "a3945baf-4708-4a0b-8a9b-1a5448ee4bc7"
		date = "2023-10-23"
		modified = "2023-10-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_HLoader.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2360a69e5fd7217e977123c81d3dbb60bf4763a9dae6949bc1900234f7762df1"
		logic_hash = "0383485b6bbcdae210a6c949f6796023b2f7ec3f1edbd2116207fc2b75a67849"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a48ec79f07a6a53611b1d1e8fe938513ec0ea19344126e07331b48b028cb877e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$seq_main = { 74 ?? 49 89 C7 48 89 D8 4C 89 FF E8 ?? ?? ?? ?? 48 89 DF 31 F6 BA ?? ?? ?? ?? 4C 89 65 ?? 4D 89 F4 4C 89 F1 4C 8B 75 ?? 41 FF 56 ?? }
		$seq_exec = { 48 B8 00 00 00 00 00 00 00 E0 48 89 45 ?? 4C 8D 6D ?? BF 11 00 00 00 E8 ?? ?? ?? ?? 0F 10 45 ?? 0F 11 45 ?? 48 BF 65 78 65 63 46 69 6C 65 48 BE 20 65 72 72 6F 72 20 EF }
		$seq_rename = { 41 89 DE 84 DB 74 ?? 48 8B 7D ?? FF 15 ?? ?? ?? ?? E9 ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ?? }

	condition:
		2 of ($seq*)
}