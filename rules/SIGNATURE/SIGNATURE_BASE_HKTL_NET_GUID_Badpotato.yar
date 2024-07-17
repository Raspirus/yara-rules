import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Badpotato : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "8bee12fc-fc29-5256-b559-d914ef202c0c"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/BeichenDream/BadPotato"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3067-L3081"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "52b80fa9f4738fb8d9ce14f2881e19122219a13e9fc3acdf87ed7bfea371ebc4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "0527a14f-1591-4d94-943e-d6d784a50549" ascii wide
		$typelibguid0up = "0527A14F-1591-4D94-943E-D6D784A50549" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}