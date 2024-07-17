rule SIGNATURE_BASE_HKTL_NET_GUID_Stealer : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "c721a0ac-e898-52aa-9bdf-a19bc0bd783d"
		date = "2020-12-29"
		modified = "2023-04-06"
		reference = "https://github.com/malwares/Stealer"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4294-L4312"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "541836ece736557383d209a424a0fa9fb9df69a669d8f1cf8d1bdb41bd27af57"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "8fcd4931-91a2-4e18-849b-70de34ab75df" ascii wide
		$typelibguid0up = "8FCD4931-91A2-4E18-849B-70DE34AB75DF" ascii wide
		$typelibguid1lo = "e48811ca-8af8-4e73-85dd-2045b9cca73a" ascii wide
		$typelibguid1up = "E48811CA-8AF8-4E73-85DD-2045B9CCA73A" ascii wide
		$typelibguid2lo = "d3d8a1cc-e123-4905-b3de-374749122fcf" ascii wide
		$typelibguid2up = "D3D8A1CC-E123-4905-B3DE-374749122FCF" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}