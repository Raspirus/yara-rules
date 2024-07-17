rule SIGNATURE_BASE_Irontiger_HTTP_SOCKS_Proxy_Soexe : FILE
{
	meta:
		description = "Iron Tiger Toolset - HTTP SOCKS Proxy soexe"
		author = "Cyber Safety Solutions, Trend Micro"
		id = "6ead3d61-c1e3-55d1-894e-ab57bcd09cde"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "http://goo.gl/T5fSJC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_irontiger_trendmicro.yar#L137-L152"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f262751727de3d47a8d7cdc1f8ba8d92f4f60e22bc4e897bd5e53a8f2c118c95"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$str1 = "listen SOCKET error." wide ascii
		$str2 = "WSAAsyncSelect SOCKET error." wide ascii
		$str3 = "new SOCKETINFO error!" wide ascii
		$str4 = "Http/1.1 403 Forbidden" wide ascii
		$str5 = "Create SOCKET error." wide ascii

	condition:
		uint16(0)==0x5a4d and (3 of ($str*))
}