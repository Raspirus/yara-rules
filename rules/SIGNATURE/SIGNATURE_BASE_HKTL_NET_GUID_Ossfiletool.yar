rule SIGNATURE_BASE_HKTL_NET_GUID_Ossfiletool : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "fa9aeae1-2aa5-51af-81e2-22a1b6fcda81"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/B1eed/OSSFileTool"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1424-L1438"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "2158671f0372080a7f78a7c6804d8be6715953545e23733ef1db091b2d849f2f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "207aca5d-dcd6-41fb-8465-58b39efcde8b" ascii wide
		$typelibguid0up = "207ACA5D-DCD6-41FB-8465-58B39EFCDE8B" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}