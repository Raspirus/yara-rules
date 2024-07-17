rule SIGNATURE_BASE_Bronzebutler_Daserf_C_1 : FILE
{
	meta:
		description = "Detects malware / hacktool sample from Bronze Butler incident"
		author = "Florian Roth (Nextron Systems)"
		id = "62a5cc4a-7c58-5e4d-ac23-8d1f850a540a"
		date = "2017-10-14"
		modified = "2023-12-05"
		reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_bronze_butler.yar#L38-L78"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0b0c05db41d6b6ac48b31d8c22aead301470f465c2840ddc98ed9577d0aaa50b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a4afd9df1b4cc014c3a89d7b4a560fa3e368b02286c42841762714b23e68cc05"
		hash2 = "90ac1fb148ded4f46949a5fea4cd8c65d4ea9585046d66459328a5866f8198b2"
		hash3 = "331ac0965b50958db49b7794cc819b2945d7b5e5e919c185d83e997e205f107b"
		hash4 = "b1fdc6dc330e78a66757b77cc67a0e9931b777cd7af9f839911eecb74c04420a"
		hash5 = "15abe7b1355cd35375de6dde57608f6d3481755fdc9e71d2bfc7c7288db4cd92"
		hash6 = "85544d2bcaf8e6ca32bbc0a9e9583c9db1dce837043f555a7ff66363d5858439"
		hash7 = "2dc24622c1e91642a21a64c0dd31cbe953e8f77bd3d6abcf2c4676c3b11bb162"
		hash8 = "2bdb88fa24cffba240b60416835189c76a9920b6c3f6e09c3c4b171c2f57031c"

	strings:
		$s1 = "(c) 2010 DYAMAR EnGineerinG, All rights reserved, http://www.dyamar.com." fullword ascii
		$s2 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; SV1)" fullword ascii
		$a1 = "ndkkwqgcm" fullword ascii
		$a2 = "RtlGetCo" fullword ascii
		$a3 = "hutils" fullword ascii
		$b1 = "%USERPROFILE%\\System" fullword ascii
		$b2 = "msid.dat" fullword ascii
		$b3 = "DRIVE_REMOTE" fullword wide
		$b4 = "%s%s%s%s%s%s%s%s%s%s%s%s" fullword ascii
		$b5 = "jcbhe.asp" fullword ascii
		$b6 = "edset.asp" fullword ascii
		$b7 = "bxcve.asp" fullword ascii
		$b8 = "hcvery.php" fullword ascii
		$b9 = "ynhkef.php" fullword ascii
		$b10 = "dkgwey.php" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and (pe.imphash()=="088382f4887e3b2c4bd5157f2d72b618" or all of ($a*) or 4 of them )
}