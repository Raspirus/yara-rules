rule SIGNATURE_BASE_HKTL_NET_GUID_Sharppack : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "633d074a-b8c2-5148-ad80-6226b99be818"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/Lexus89/SharpPack"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1504-L1532"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b3f86041560b8358c5408d73d8eb847d600e66ca2c9900f53d193902e4ae8eee"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid1lo = "b59c7741-d522-4a41-bf4d-9badddebb84a" ascii wide
		$typelibguid1up = "B59C7741-D522-4A41-BF4D-9BADDDEBB84A" ascii wide
		$typelibguid2lo = "fd6bdf7a-fef4-4b28-9027-5bf750f08048" ascii wide
		$typelibguid2up = "FD6BDF7A-FEF4-4B28-9027-5BF750F08048" ascii wide
		$typelibguid3lo = "6dd22880-dac5-4b4d-9c91-8c35cc7b8180" ascii wide
		$typelibguid3up = "6DD22880-DAC5-4B4D-9C91-8C35CC7B8180" ascii wide
		$typelibguid5lo = "f3037587-1a3b-41f1-aa71-b026efdb2a82" ascii wide
		$typelibguid5up = "F3037587-1A3B-41F1-AA71-B026EFDB2A82" ascii wide
		$typelibguid6lo = "41a90a6a-f9ed-4a2f-8448-d544ec1fd753" ascii wide
		$typelibguid6up = "41A90A6A-F9ED-4A2F-8448-D544EC1FD753" ascii wide
		$typelibguid7lo = "3787435b-8352-4bd8-a1c6-e5a1b73921f4" ascii wide
		$typelibguid7up = "3787435B-8352-4BD8-A1C6-E5A1B73921F4" ascii wide
		$typelibguid8lo = "fdd654f5-5c54-4d93-bf8e-faf11b00e3e9" ascii wide
		$typelibguid8up = "FDD654F5-5C54-4D93-BF8E-FAF11B00E3E9" ascii wide
		$typelibguid9lo = "aec32155-d589-4150-8fe7-2900df4554c8" ascii wide
		$typelibguid9up = "AEC32155-D589-4150-8FE7-2900DF4554C8" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}