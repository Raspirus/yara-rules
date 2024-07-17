import "pe"


rule SIGNATURE_BASE_Hvs_APT37_Smb_Scanner : FILE
{
	meta:
		description = "Unknown smb login scanner used by APT37"
		author = "Marc Stroebel"
		id = "89a5cc32-f151-583d-823d-692de2c2b084"
		date = "2020-12-15"
		modified = "2023-12-05"
		reference = "https://www.hybrid-analysis.com/sample/d16163526242508d6961f061aaffe3ae5321bd64d8ceb6b2788f1570757595fc?environmentId=2"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_lazarus_dec20.yar#L2-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0bea71db7052f1c22c01cfbf710d4ed24651cbbd8b0fd29f09dfd49c4e314028"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Scan.exe StartIP EndIP ThreadCount logfilePath [Username Password Deep]" fullword ascii
		$s2 = "%s - %s:(Username - %s / Password - %s" fullword ascii
		$s3 = "Load mpr.dll Error " fullword ascii
		$s4 = "Load Netapi32.dll Error " fullword ascii
		$s5 = "%s U/P not Correct! - %d" fullword ascii
		$s6 = "GetNetWorkInfo Version 1.0" fullword wide
		$s7 = "Hello World!" fullword wide
		$s8 = "%s Error: %ld" fullword ascii
		$s9 = "%s U/P Correct!" fullword ascii
		$s10 = "%s --------" fullword ascii
		$s11 = "%s%-30s%I64d" fullword ascii
		$s12 = "%s%-30s(DIR)" fullword ascii
		$s13 = "%04d-%02d-%02d %02d:%02d" fullword ascii
		$s14 = "Share:              Local Path:                   Uses:   Descriptor:" fullword ascii
		$s15 = "Share:              Type:                   Remark:" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and (10 of them )
}