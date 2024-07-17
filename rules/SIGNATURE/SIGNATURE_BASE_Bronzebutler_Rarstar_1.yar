import "pe"


rule SIGNATURE_BASE_Bronzebutler_Rarstar_1 : FILE
{
	meta:
		description = "Detects malware / hacktool sample from Bronze Butler incident"
		author = "Florian Roth (Nextron Systems)"
		id = "770270b3-6743-5efb-84d8-b63f1df800d9"
		date = "2017-10-14"
		modified = "2023-12-05"
		reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_bronze_butler.yar#L142-L158"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0e418e595020d91c575051c3b1639b09efad150c625b62eec3d1331f9792641b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "0fc1b4fdf0dc5373f98de8817da9380479606f775f5aa0b9b0e1a78d4b49e5f4"

	strings:
		$s1 = "Mozilla/4.0+(compatible;+MSIE+8.0;+Windows+NT+6.0;+SV1)" fullword wide
		$s2 = "http://www.google.co.jp" fullword wide
		$s3 = "16D73E22-873D-D58E-4F42-E6055BC9825E" fullword ascii
		$s4 = "\\*.rar" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 2 of them )
}