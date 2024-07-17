rule SIGNATURE_BASE_HKTL_NET_GUID_Keethief : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "71fef0e9-223a-5834-9d1c-f3fb8b66a809"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/GhostPack/KeeThief"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4023-L4046"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "032f0453dc8e235b9326705c619929135cfc71840ab39669ae21c14b93568c75"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid1lo = "39aa6f93-a1c9-497f-bad2-cc42a61d5710" ascii wide
		$typelibguid1up = "39AA6F93-A1C9-497F-BAD2-CC42A61D5710" ascii wide
		$typelibguid3lo = "3fca8012-3bad-41e4-91f4-534aa9a44f96" ascii wide
		$typelibguid3up = "3FCA8012-3BAD-41E4-91F4-534AA9A44F96" ascii wide
		$typelibguid4lo = "ea92f1e6-3f34-48f8-8b0a-f2bbc19220ef" ascii wide
		$typelibguid4up = "EA92F1E6-3F34-48F8-8B0A-F2BBC19220EF" ascii wide
		$typelibguid5lo = "c23b51c4-2475-4fc6-9b3a-27d0a2b99b0f" ascii wide
		$typelibguid5up = "C23B51C4-2475-4FC6-9B3A-27D0A2B99B0F" ascii wide
		$typelibguid7lo = "80ba63a4-7d41-40e9-a722-6dd58b28bf7e" ascii wide
		$typelibguid7up = "80BA63A4-7D41-40E9-A722-6DD58B28BF7E" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}