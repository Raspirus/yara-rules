
rule SIGNATURE_BASE_Uboatrat_Dropper : FILE
{
	meta:
		description = "Detects UBoatRAT Dropper"
		author = "Florian Roth (Nextron Systems)"
		id = "f3d4e333-1282-5f6e-9294-628a8230d2a5"
		date = "2017-11-29"
		modified = "2023-12-05"
		reference = "https://researchcenter.paloaltonetworks.com/2017/11/unit42-uboatrat-navigates-east-asia/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_uboat_rat.yar#L52-L69"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "6f8dcc8559fa0ab1644ef6bab9bc875f3d62391c157b373e0355ad03d35e5601"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "f4c659238ffab95e87894d2c556f887774dce2431e8cb87f881df4e4d26253a3"

	strings:
		$s1 = "GetCurrenvackageId" fullword ascii
		$s2 = "fghijklmnopq" fullword ascii
		$s3 = "23456789:;<=>?@ABCDEFGHIJKLMNOPQ" fullword ascii
		$s4 = "PMM/dd/y" fullword ascii
		$s5 = "bad all" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}