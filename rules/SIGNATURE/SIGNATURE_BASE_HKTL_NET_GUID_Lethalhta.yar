rule SIGNATURE_BASE_HKTL_NET_GUID_Lethalhta : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "e8e1ad03-a5f0-5508-b78d-0de7bdaf4704"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/codewhitesec/LethalHTA"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3083-L3099"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c9957f9e0838c5c708afa1651aedb9c6cb003f53c1ce38b200b1526da8fa3a65"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "784cde17-ff0f-4e43-911a-19119e89c43f" ascii wide
		$typelibguid0up = "784CDE17-FF0F-4E43-911A-19119E89C43F" ascii wide
		$typelibguid1lo = "7e2de2c0-61dc-43ab-a0ec-c27ee2172ea6" ascii wide
		$typelibguid1up = "7E2DE2C0-61DC-43AB-A0EC-C27EE2172EA6" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}