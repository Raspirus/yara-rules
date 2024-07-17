rule SIGNATURE_BASE_CN_Disclosed_20180208_System3 : FILE
{
	meta:
		description = "Detects malware from disclosed CN malware set"
		author = "Florian Roth (Nextron Systems)"
		id = "097f4506-295d-5066-8895-2148436731c1"
		date = "2018-02-08"
		modified = "2023-12-05"
		reference = "https://twitter.com/cyberintproject/status/961714165550342146"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_cn_campaign_njrat.yar#L57-L74"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8292ae1de39c57bc5ed6fa078570e92dbcd22cd13d5b5f22d158986708139fbe"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "73fa84cff51d384c2d22d9e53fc5d42cb642172447b07e796c81dd403fb010c2"

	strings:
		$a1 = "WmiPrvSE.exe" fullword wide
		$s1 = "C:\\Users\\sgl\\AppData\\Local\\" ascii
		$s2 = "Temporary Projects\\WmiPrvSE\\" ascii
		$s3 = "$15a32a5d-4906-458a-8f57-402311afc1c1" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and $a1 and 1 of ($s*)
}