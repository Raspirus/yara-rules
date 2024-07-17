
rule SIGNATURE_BASE_MAL_RANSOM_Darkbit_Feb23_1 : FILE
{
	meta:
		description = "Detects indicators found in DarkBit ransomware"
		author = "Florian Roth"
		id = "d209a0c2-f649-5fb1-9ecd-f1c35caa796f"
		date = "2023-02-13"
		modified = "2023-12-05"
		reference = "https://twitter.com/idonaor1/status/1624703255770005506?s=12&t=mxHaauzwR6YOj5Px8cIeIw"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ransom_darkbit_feb23.yar#L2-L23"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ba1baea7cb7362160c4b00b0355000a789b238c1ec82b840479c04028e6ca3ab"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = ".onion" ascii
		$s2 = "GetMOTWHostUrl"
		$x1 = "hus31m7c7ad.onion"
		$x2 = "iw6v2p3cruy"
		$xn1 = "You will receive decrypting key after the payment."

	condition:
		uint16(0)==0x5a4d and filesize <10MB and (1 of ($x*) or 2 of them ) or 4 of them or ( filesize <10MB and $xn1)
}