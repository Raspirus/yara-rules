rule SIGNATURE_BASE_MAL_Burningumbrella_Sample_16 : FILE
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		author = "Florian Roth (Nextron Systems)"
		id = "8b1970bd-571e-5c53-9170-1605c69d9d6d"
		date = "2018-05-04"
		modified = "2023-12-05"
		reference = "https://401trg.pw/burning-umbrella/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_winnti_burning_umbrella.yar#L250-L263"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "2d0ee163e7f6f04bfe6941575d0916e18ce2e5c2426e0af326c9567560df3122"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "58bb3859e02b8483e9f84cc56fbd964486e056ef28e94dd0027d361383cc4f4a"

	strings:
		$s1 = "http://netimo.net 0" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <500KB and all of them
}