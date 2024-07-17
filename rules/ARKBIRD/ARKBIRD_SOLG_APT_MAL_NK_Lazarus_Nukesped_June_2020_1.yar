rule ARKBIRD_SOLG_APT_MAL_NK_Lazarus_Nukesped_June_2020_1 : FILE
{
	meta:
		description = "Detect NukeSped malware used by APT Lazarus"
		author = "Arkbird_SOLG"
		id = "7a5b27df-43bd-544d-8d0f-72e58ce3064c"
		date = "2020-06-11"
		modified = "2020-06-12"
		reference = "https://twitter.com/batrix20/status/1270924079826997248"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-06-12/Lazarus/Lazarus_June_2020_1.yar#L28-L54"
		license_url = "N/A"
		logic_hash = "b1332eb255f8ae9ae6a68ef8ef86d9f5472584cae8161c27186e341990df7eae"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "90ea1c7806e2d638f4a942b36a533a1da61adedd05a6d80ea1e09527cf2d839b"

	strings:
		$s1 = "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X" fullword wide
		$s2 = "<htr<jtb<lt6<tt&<wt" fullword ascii
		$s3 = "Content-Disposition: form-data; name=\"file\"; filename=\"%s\"" fullword ascii
		$s4 = "Content-Type: multipart/form-data; boundary=" fullword wide
		$s5 = "POST" fullword ascii
		$s6 = "Content-Type: octet-stream" fullword ascii
		$s7 = "CONOUT$" fullword ascii
		$s8 = "cmd.exe /c" fullword ascii
		$s9 = "2>&1" fullword ascii
		$s10 = "WINHTTP.dll" fullword ascii
		$s11 = "WinHttpSendRequest" fullword wide
		$s12 = "ObtainUserAgentString" fullword ascii
		$s13 = "WS2_32.dll" fullword ascii
		$s14 = "WinHttpReceiveResponse" fullword ascii
		$s15 = "GetLogicalDrives" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and (pe.imphash()=="c8379f0eeeb3a522f1dd75aa5f1500b0" or 12 of them )
}