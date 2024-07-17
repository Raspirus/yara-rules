rule ELASTIC_Windows_Trojan_Garble_Eae7F2F7 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Garble (Windows.Trojan.Garble)"
		author = "Elastic Security"
		id = "eae7f2f7-49b3-427c-9cf3-cce64d772c78"
		date = "2022-06-08"
		modified = "2022-09-29"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Garble.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4820a1ec99981e03675a86c4c01acba6838f04945b5f753770b3de4e253e1b8c"
		logic_hash = "5d88579b0f0f71b8b4310c141fb243f39696e158227da0a1e0140b030b783c65"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b72b8d475ef50a5e703d741f195d8ce0916f46ee5744c5bc7c8d452ab23df388"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = ".\"G!-$G#-&J%.(G'-*G)-,J+..G--0G/-2J1.4G3-6G5-8J7.:G9-<G;->J=+@A?-BAA*DAC*FAE*HFG+JAI-LAK*NAM*PAO*RFQ+TAS-VAU9"

	condition:
		all of them
}