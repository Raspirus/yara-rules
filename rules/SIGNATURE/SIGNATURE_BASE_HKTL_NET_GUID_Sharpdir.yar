import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpdir : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "f64ed564-d198-59e8-9abe-b2814b95c85f"
		date = "2021-01-21"
		modified = "2023-04-06"
		reference = "https://github.com/jnqpblc/SharpDir"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4693-L4707"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "23eb7b88f9685457a6cdaa8161fcbc6ea60634a4f01c67a4a1307618a6f8fa14"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "c7a07532-12a3-4f6a-a342-161bb060b789" ascii wide
		$typelibguid0up = "C7A07532-12A3-4F6A-A342-161BB060B789" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}