import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Change_Lockscreen : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "a817c6e8-95f9-56c6-97b8-4be06658629f"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/nccgroup/Change-Lockscreen"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2307-L2321"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "92ec9daecd17c8b0aa92f266b2cd81e0198a28d41e43d526bc94b9a2df23015b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "78642ab3-eaa6-4e9c-a934-e7b0638bc1cc" ascii wide
		$typelibguid0up = "78642AB3-EAA6-4E9C-A934-E7B0638BC1CC" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}