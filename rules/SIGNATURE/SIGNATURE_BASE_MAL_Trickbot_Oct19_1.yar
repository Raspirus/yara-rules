rule SIGNATURE_BASE_MAL_Trickbot_Oct19_1 : FILE
{
	meta:
		description = "Detects Trickbot malware"
		author = "Florian Roth (Nextron Systems)"
		id = "b428cbf9-0796-5a01-9b98-28e1bc6827cc"
		date = "2019-10-02"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_trickbot.yar#L3-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "fef15c0bda6dc2b28f34791da3ca68a03f7368b63ead17e631a2d4f05d1b40e2"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "58852140a2dc30e799b7d50519c56e2fd3bb506691918dbf5d4244cc1f4558a2"
		hash2 = "aabf54eb27de3d72078bbe8d99a92f5bcc1e43ff86774eb5321ed25fba5d27d4"
		hash3 = "9d6e4ad7f84d025bbe9f95e74542e7d9f79e054f6dcd7b37296f01e7edd2abae"

	strings:
		$s1 = "Celestor@hotmail.com" fullword ascii
		$s2 = "\\txtPassword" ascii
		$s14 = "Invalid Password, try again!" fullword wide
		$op1 = { 78 c4 40 00 ff ff ff ff b4 47 41 }
		$op2 = { 9b 68 b2 34 46 00 eb 14 8d 55 e4 8d 45 e8 52 50 }

	condition:
		uint16(0)==0x5a4d and filesize <=2000KB and 3 of them
}