rule SIGNATURE_BASE_Xtreme_Sep17_3 : FILE
{
	meta:
		description = "Detects XTREME sample analyzed in September 2017"
		author = "Florian Roth (Nextron Systems)"
		id = "160673ea-b263-520a-a1c1-da0f3e920f12"
		date = "2017-09-27"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_xtreme_rat.yar#L55-L69"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c110863028ab1f557270e52de608179ce582a47e0a20994f83d385ed285bda9a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "f540a4cac716438da0c1c7b31661abf35136ea69b963e8f16846b96f8fd63dde"

	strings:
		$s2 = "Keylogg" fullword ascii
		$s4 = "XTREME" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <700KB and all of them )
}