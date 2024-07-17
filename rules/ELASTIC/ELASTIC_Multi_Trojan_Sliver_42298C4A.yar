
rule ELASTIC_Multi_Trojan_Sliver_42298C4A : FILE MEMORY
{
	meta:
		description = "Detects Multi Trojan Sliver (Multi.Trojan.Sliver)"
		author = "Elastic Security"
		id = "42298c4a-fcea-4c5a-b213-32db00e4eb5a"
		date = "2021-10-20"
		modified = "2022-01-14"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Multi_Trojan_Sliver.yar#L1-L25"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3b45aae401ac64c055982b5f3782a3c4c892bdb9f9a5531657d50c27497c8007"
		logic_hash = "a84bdb51fcdeb4629365bdb727b53087604ee0eb112c8d6c3ecf315598ec678a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0734b090ea10abedef4d9ed48d45c834dd5cf8e424886a5be98e484f69c5e12a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "multi"

	strings:
		$a1 = ").RequestResend"
		$a2 = ").GetPrivInfo"
		$a3 = ").GetReconnectIntervalSeconds"
		$a4 = ").GetPivotID"
		$a5 = "name=PrivInfo"
		$a6 = "name=ReconnectIntervalSeconds"
		$a7 = "name=PivotID"

	condition:
		2 of them
}