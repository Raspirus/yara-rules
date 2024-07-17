rule SIGNATURE_BASE_PLEAD_Downloader_Jun18_1 : FILE
{
	meta:
		description = "Detects PLEAD Downloader"
		author = "Florian Roth (Nextron Systems)"
		id = "19d588d8-1f03-5f34-b82e-b645c28a19a4"
		date = "2018-06-16"
		modified = "2023-12-05"
		reference = "https://blog.jpcert.or.jp/2018/06/plead-downloader-used-by-blacktech.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_plead_downloader.yar#L1-L21"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "82fa4629aeb67a657af8b40527414e59d1c45a7c4e3c68398d3472c080c9487b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a26df4f62ada084a596bf0f603691bc9c02024be98abec4a9872f0ff0085f940"

	strings:
		$s1 = "%02d:%02d:%02d" ascii fullword
		$s2 = "%02d-%02d-%02d" ascii fullword
		$s3 = "1111%02d%02d%02d_%02d%02d2222" ascii fullword
		$a1 = "Scanning..." wide fullword
		$a2 = "Checking..." wide fullword

	condition:
		uint16(0)==0x5a4d and filesize <200KB and ( all of ($s*) or (2 of ($s*) and 1 of ($a*)))
}