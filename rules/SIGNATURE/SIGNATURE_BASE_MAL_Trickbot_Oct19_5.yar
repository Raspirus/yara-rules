rule SIGNATURE_BASE_MAL_Trickbot_Oct19_5 : FILE
{
	meta:
		description = "Detects Trickbot malware"
		author = "Florian Roth (Nextron Systems)"
		id = "b3034f0c-5fd9-58a2-866f-9100e3a56f39"
		date = "2019-10-02"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_trickbot.yar#L79-L96"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e304b236dd58faa0e6fdd73bc93c24f6ff0ec6c1f9a54b104f8e87441834e22b"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "58852140a2dc30e799b7d50519c56e2fd3bb506691918dbf5d4244cc1f4558a2"
		hash2 = "aabf54eb27de3d72078bbe8d99a92f5bcc1e43ff86774eb5321ed25fba5d27d4"
		hash3 = "9ecc794ec77ce937e8c835d837ca7f0548ef695090543ed83a7adbc07da9f536"
		hash4 = "9d6e4ad7f84d025bbe9f95e74542e7d9f79e054f6dcd7b37296f01e7edd2abae"

	strings:
		$s1 = "LoadShellCode" fullword ascii
		$s2 = "pShellCode" fullword ascii
		$s3 = "InitShellCode" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <=2000KB and 2 of them
}