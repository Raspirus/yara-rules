
rule SIGNATURE_BASE_Minirat_Gen_1 : FILE
{
	meta:
		description = "Detects Mini RAT malware"
		author = "Florian Roth (Nextron Systems)"
		id = "65d89762-2fd0-5c6a-b706-92d77a03089a"
		date = "2018-01-22"
		modified = "2023-12-05"
		reference = "https://www.eff.org/deeplinks/2018/01/dark-caracal-good-news-and-bad-news"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_darkcaracal.yar#L12-L30"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "53c4ba16ae2c3eb3a6c7371e7fc8b962cfbee5b70abd8267294834eac3e55769"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "091ae8d5649c4e040d25550f2cdf7f1ddfc9c698e672318eb1ab6303aa1cf85b"
		hash2 = "b6ac374f79860ae99736aaa190cce5922a969ab060d7ae367dbfa094bfe4777d"
		hash3 = "ba4e063472a2559b4baa82d5272304a1cdae6968145c5ef221295c90e88458e2"
		hash4 = "ed97719c008422925ae21ff34448a8c35ee270a428b0478e24669396761d0790"
		hash5 = "675c3d96070dc9a0e437f3e1b653b90dbc6700b0ec57379d4139e65f7d2799cd"

	strings:
		$x1 = "\\Mini rat\\" ascii
		$x2 = "\\Projects\\ali\\Clever Components v7\\" ascii

	condition:
		uint16(0)==0x5a4d and filesize <7000KB and 1 of them
}