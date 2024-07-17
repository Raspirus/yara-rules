import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Dohc2 : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "0bb38f10-ca5c-5c18-97c9-540b6367d150"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/SpiderLabs/DoHC2"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2211-L2225"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d94760229bd6df29f7e281ee9d38068699d6529b93ed90c8846635bd496d602a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "9877a948-2142-4094-98de-e0fbb1bc4062" ascii wide
		$typelibguid0up = "9877A948-2142-4094-98DE-E0FBB1BC4062" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}