rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpbox : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "fda1a67f-d746-5ddb-a33f-97d608b13bc9"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/P1CKLES/SharpBox"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3264-L3278"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "dba572c1c52bc887600e5e674403b3a43578ca43c8ea4d6b34530796ef1de0d0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "616c1afb-2944-42ed-9951-bf435cadb600" ascii wide
		$typelibguid0up = "616C1AFB-2944-42ED-9951-BF435CADB600" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}