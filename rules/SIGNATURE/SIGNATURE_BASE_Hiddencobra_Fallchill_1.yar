import "pe"


rule SIGNATURE_BASE_Hiddencobra_Fallchill_1 : FILE
{
	meta:
		description = "Auto-generated rule"
		author = "Florian Roth (Nextron Systems)"
		id = "5bbeb5ba-93d7-5903-9132-749afe5776ae"
		date = "2017-11-15"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-318A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ta17_318A.yar#L51-L77"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8e6215a81272ea457318dd83eff9e1902c5e1d1a124ff674b145f2dc5e4a3711"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a606716355035d4a1ea0b15f3bee30aad41a2c32df28c2d468eafd18361d60d6"

	strings:
		$s1 = "REGSVR32.EXE.MUI" fullword wide
		$s2 = "Microsoft Corporation. All rights reserved." fullword wide
		$s3 = "c%sd.e%sc %s > \"%s\" 2>&1" fullword wide
		$s4 = "\" goto Loop" fullword ascii
		$e1 = "xolhvhlxpvg" fullword ascii
		$e2 = "tvgslhgybmanv" fullword ascii
		$e3 = "CivagvTllosvok32Smakhslg" fullword ascii
		$e4 = "GvgCfiivmgDrivxglibW" fullword ascii
		$e5 = "OkvmPilxvhhTlpvm" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and (pe.imphash()=="6135d9bc3591ae7bc72d070eadd31755" or 3 of ($s*) or 4 of them )
}