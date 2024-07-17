import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_IIS_Backdoor : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "44264dd9-f8e9-5a60-847f-94378e07a327"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/WBGlIl/IIS_backdoor"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2123-L2139"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "fbf6c641c9cede86867a88b62d5287d918edd67ae9f7228b5243d050a6487345"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "3fda4aa9-6fc1-473f-9048-7edc058c4f65" ascii wide
		$typelibguid0up = "3FDA4AA9-6FC1-473F-9048-7EDC058C4F65" ascii wide
		$typelibguid1lo = "73ca4159-5d13-4a27-8965-d50c41ab203c" ascii wide
		$typelibguid1up = "73CA4159-5D13-4A27-8965-D50C41AB203C" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}