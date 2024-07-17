rule SIGNATURE_BASE_Rehashed_RAT_2 : FILE
{
	meta:
		description = "Detects malware from Rehashed RAT incident"
		author = "Florian Roth (Nextron Systems)"
		id = "fcf82155-10da-56b7-879b-841c4ae5023b"
		date = "2017-09-08"
		modified = "2023-12-05"
		reference = "https://blog.fortinet.com/2017/09/05/rehashed-rat-used-in-apt-campaign-against-vietnamese-organizations"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_rehashed_rat.yar#L41-L67"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "96c4582981792eb5f8180c06a5fe824fd439cfa0ede294eccff3afa7d318a6e9"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "49efab1dedc6fffe5a8f980688a5ebefce1be3d0d180d5dd035f02ce396c9966"

	strings:
		$x1 = "dalat.dulichovietnam.net" fullword ascii
		$x2 = "web.Thoitietvietnam.org" fullword ascii
		$a1 = "User-Agent: Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64)" fullword ascii
		$a2 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3" ascii
		$s1 = "GET /%s%s%s%s HTTP/1.1" fullword ascii
		$s2 = "http://%s:%d/%s%s%s%s" fullword ascii
		$s3 = "{521338B8-3378-58F7-AFB9-E7D35E683BF8}" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and (pe.imphash()=="9c4c648f4a758cbbfe28c8850d82f931" or (1 of ($x*) or 3 of them ))) or (4 of them )
}