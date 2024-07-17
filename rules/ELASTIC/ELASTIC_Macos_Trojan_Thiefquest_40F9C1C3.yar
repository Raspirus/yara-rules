rule ELASTIC_Macos_Trojan_Thiefquest_40F9C1C3 : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Thiefquest (MacOS.Trojan.Thiefquest)"
		author = "Elastic Security"
		id = "40f9c1c3-29f8-4699-8f66-9b7ddb08f92d"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Thiefquest.yar#L64-L82"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e402063ca317867de71e8e3189de67988e2be28d5d773bbaf75618202e80f9f6"
		logic_hash = "546edc2d6d715eac47e7a8d3ceb91cf314fa6dbee04f0475a5c4a84ba53fd722"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "27ec200781541d5b1abc96ffbb54c428b773bffa0744551bbacd605c745b6657"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 77 47 72 33 31 30 50 6D 72 7A 30 30 30 30 30 37 33 00 33 7C 49 56 7C 6A 30 30 }

	condition:
		all of them
}