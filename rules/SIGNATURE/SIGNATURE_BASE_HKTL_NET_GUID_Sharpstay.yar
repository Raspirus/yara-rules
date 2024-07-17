rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpstay : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "e5bde5a9-8e09-59ce-ad01-e29836813cf8"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/0xthirteen/SharpStay"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3471-L3485"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3750df9725c739fad99d2ce5d3fab0c84112c1efb2e4e5a1348501174c4ce494"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "2963c954-7b1e-47f5-b4fa-2fc1f0d56aea" ascii wide
		$typelibguid0up = "2963C954-7B1E-47F5-B4FA-2FC1F0D56AEA" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}