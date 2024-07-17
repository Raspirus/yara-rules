rule CAPE_Socks5Systemz : FILE
{
	meta:
		description = "Socks5Systemz Payload"
		author = "kevoreilly"
		id = "75831382-bb43-554e-93b1-f54a2255d8b9"
		date = "2024-05-22"
		modified = "2024-05-22"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Socks5Systemz.yar#L1-L18"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "44b83b6d2ab39b4258ae0d97d00d02afdbb62a3973fd788584e4dea9db69cc1b"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Socks5Systemz Payload"
		packed = "9b997d0de3fe83091726919a0dc653e22f8f8b20b1bb7d0b8485652e88396f29"

	strings:
		$chunk1 = {0F B6 84 8A [4] E9 [3] (00|FF)}
		$chunk2 = {0F B6 04 8D [4] E9 [3] (00|FF)}
		$chunk3 = {0F B6 04 8D [4] E9 [3] (00|FF)}
		$chunk4 = {0F B6 04 8D [4] E9 [3] (00|FF)}
		$chunk5 = {66 0F 6F 05 [4] E9 [3] (00|FF)}
		$chunk6 = {F0 0F B1 95 [4] E9 [3] (00|FF)}
		$chunk7 = {83 FA 04 E9 [3] (00|FF)}

	condition:
		uint16(0)==0x5A4D and 6 of them
}