rule SIGNATURE_BASE_HKTL_NET_GUID_Clr_Meterpreter : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "1d8a9717-4d80-5fb1-9c57-9b5f6c5a18b0"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/OJ/clr-meterpreter"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1268-L1292"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "15fb4e51fc1473fbee3b08c2a94b6a984cc5b9c92c8aab5641f161aef8b5f01b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "6840b249-1a0e-433b-be79-a927696ea4b3" ascii wide
		$typelibguid0up = "6840B249-1A0E-433B-BE79-A927696EA4B3" ascii wide
		$typelibguid1lo = "67c09d37-ac18-4f15-8dd6-b5da721c0df6" ascii wide
		$typelibguid1up = "67C09D37-AC18-4F15-8DD6-B5DA721C0DF6" ascii wide
		$typelibguid2lo = "e05d0deb-d724-4448-8c4c-53d6a8e670f3" ascii wide
		$typelibguid2up = "E05D0DEB-D724-4448-8C4C-53D6A8E670F3" ascii wide
		$typelibguid3lo = "c3cc72bf-62a2-4034-af66-e66da73e425d" ascii wide
		$typelibguid3up = "C3CC72BF-62A2-4034-AF66-E66DA73E425D" ascii wide
		$typelibguid4lo = "7ace3762-d8e1-4969-a5a0-dcaf7b18164e" ascii wide
		$typelibguid4up = "7ACE3762-D8E1-4969-A5A0-DCAF7B18164E" ascii wide
		$typelibguid5lo = "3296e4a3-94b5-4232-b423-44f4c7421cb3" ascii wide
		$typelibguid5up = "3296E4A3-94B5-4232-B423-44F4C7421CB3" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}