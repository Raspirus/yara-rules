import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Csharpamsibypass : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "ca97004e-edc1-5b5a-ac67-e81ae24631aa"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/WayneJLee/CsharpAmsiBypass"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L858-L872"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c422c6b2dc54f5d62a4e5e85da4add5d0bf4eb5107f6778a45835649581a5517"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "4ab3b95d-373c-4197-8ee3-fe0fa66ca122" ascii wide
		$typelibguid0up = "4AB3B95D-373C-4197-8EE3-FE0FA66CA122" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}