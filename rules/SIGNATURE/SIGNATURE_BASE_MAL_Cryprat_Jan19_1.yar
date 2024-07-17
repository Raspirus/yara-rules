import "pe"


rule SIGNATURE_BASE_MAL_Cryprat_Jan19_1 : FILE
{
	meta:
		description = "Detects CrypRAT"
		author = "Florian Roth (Nextron Systems)"
		id = "f3063a16-8813-5d6c-9807-6a0725907fb5"
		date = "2019-01-07"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/mal_cryp_rat.yar#L3-L19"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "69f8a581bae1a2c411e09e8fe01a979645ef897038af868d8e9f2a2ce9188080"
		score = 90
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "Cryp_RAT" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <600KB and (pe.imphash()=="2524e5e9fe04d7bfe5efb3a5e400fe4b" or 1 of them )
}