import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpgpo_Remoteaccesspolicies : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "642c2672-2327-5a4a-af91-6e0559996908"
		date = "2020-12-21"
		modified = "2023-04-06"
		reference = "https://github.com/FSecureLABS/SharpGPO-RemoteAccessPolicies"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2597-L2611"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7d6f74ef8d34603502b26b60a1042dd531891088b9455f068bccaabaf12232b1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "fbb1abcf-2b06-47a0-9311-17ba3d0f2a50" ascii wide
		$typelibguid0up = "FBB1ABCF-2B06-47A0-9311-17BA3D0F2A50" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}