import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpview : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "2ae1bc26-c137-55ce-ae2e-3204ff07f671"
		date = "2023-03-22"
		modified = "2023-04-06"
		reference = "https://github.com/tevora-threat/SharpView"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5314-L5328"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "74c1b0ad4717b3d9494b0f1df4a51d03d0e0cbf99e5d911beaa2cc67cdd50233"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "22a156ea-2623-45c7-8e50-e864d9fc44d3" ascii wide
		$typelibguid0up = "22A156EA-2623-45C7-8E50-E864D9FC44D3" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}