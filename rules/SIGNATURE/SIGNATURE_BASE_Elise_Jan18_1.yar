rule SIGNATURE_BASE_Elise_Jan18_1 : FILE
{
	meta:
		description = "Detects Elise malware samples - fake Norton Security NavShExt.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "8e4f4ec8-5d31-5990-8c14-861423571a79"
		date = "2018-01-24"
		modified = "2023-12-05"
		reference = "https://twitter.com/blu3_team/status/955971742329135105"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_lotusblossom_elise.yar#L13-L32"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d43486db0d4263f91924da89f1922ad965ed91eadd07ae0705eecd371f31fa44"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "6dc2a49d58dc568944fef8285ad7a03b772b9bdf1fe4bddff3f1ade3862eae79"

	strings:
		$s1 = "NavShExt.dll" fullword wide
		$s2 = "Norton Security" fullword wide
		$a1 = "donotbotherme" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <250KB and (pe.imphash()=="e9478ee4ebf085d1f14f64ba96ef082f" or (1 of ($s*) and $a1))
}