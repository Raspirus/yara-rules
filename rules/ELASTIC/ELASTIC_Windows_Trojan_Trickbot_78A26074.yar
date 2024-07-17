
rule ELASTIC_Windows_Trojan_Trickbot_78A26074 : FILE MEMORY
{
	meta:
		description = "Targets psfin64.dll module containing point-of-sale recon functionality"
		author = "Elastic Security"
		id = "78a26074-dc4b-436d-8188-2a3cfdabf6db"
		date = "2021-03-29"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L530-L564"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8cd75fa8650ebcf0a6200283e474a081cc0be57307e54909ee15f4d04621dde0"
		logic_hash = "3837c22f7f9d55f03cb0bc1336798f0e2a91549c187b9f5136491cbafd26ce6e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f0446c7e1a497b93720824f4a5b72f23f00d0ee9a1607bc0c1b097109ec132a8"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "<moduleconfig><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"SetConf\" file=\"dpost\" period=\"14400\"/></a"
		$a2 = "Dpost servers unavailable" ascii fullword
		$a3 = "moduleconfig>" ascii fullword
		$a4 = "ALOHA found: %d" wide fullword
		$a5 = "BOH found: %d" wide fullword
		$a6 = "MICROS found: %d" wide fullword
		$a7 = "LANE found: %d" wide fullword
		$a8 = "RETAIL found: %d" wide fullword
		$a9 = "REG found: %d" wide fullword
		$a10 = "STORE found: %d" wide fullword
		$a11 = "POS found: %d" wide fullword
		$a12 = "DOMAIN %s" wide fullword
		$a13 = "/%s/%s/90" wide fullword
		$a14 = "CASH found: %d" wide fullword
		$a15 = "COMPUTERS:" wide fullword
		$a16 = "TERM found: %d" wide fullword

	condition:
		3 of ($a*)
}