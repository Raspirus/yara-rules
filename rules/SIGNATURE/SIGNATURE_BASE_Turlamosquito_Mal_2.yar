rule SIGNATURE_BASE_Turlamosquito_Mal_2 : FILE
{
	meta:
		description = "Detects malware sample from Turla Mosquito report"
		author = "Florian Roth (Nextron Systems)"
		id = "d23d9fe1-26e3-5012-8a88-61ebbc3fbd8f"
		date = "2018-02-22"
		modified = "2023-12-05"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_turla_mosquito.yar#L32-L52"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f1f93d3bc1c4bd55fc7558716a0a1eb7a6c4c2381a4532d37f4e3559f7c809ea"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "68c6e9dea81f082601ae5afc41870cea3f71b22bfc19bcfbc61d84786e481cb4"
		hash2 = "05254971fe3e1ca448844f8cfcfb2b0de27e48abd45ea2a3df897074a419a3f4"

	strings:
		$s1 = ".?AVFileNameParseException@ExecuteFile@@" fullword ascii
		$s3 = "no_address" fullword wide
		$s6 = "SRRRQP" fullword ascii
		$s7 = "QWVPQQ" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <600KB and (pe.imphash()=="cd918073f209c5da7a16b6c125d73746" or all of them )
}