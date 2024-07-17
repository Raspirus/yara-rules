rule SIGNATURE_BASE_CN_Disclosed_20180208_Lsls : FILE
{
	meta:
		description = "Detects malware from disclosed CN malware set"
		author = "Florian Roth (Nextron Systems)"
		id = "c6c4aa72-1a84-552f-bea0-38b332a74233"
		date = "2018-02-08"
		modified = "2023-12-05"
		reference = "https://twitter.com/cyberintproject/status/961714165550342146"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_cn_campaign_njrat.yar#L13-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c6542391e8d1a4fe4d26fd8b2dfb1fcab7b39c67dcc6495f2e5f95c4d6f8d61c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "94c6a92984df9ed255f4c644261b01c4e255acbe32ddfd0debe38b558f29a6c9"

	strings:
		$x1 = "User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)" fullword ascii

	condition:
		uint16(0)==0x457f and filesize <3000KB and $x1
}