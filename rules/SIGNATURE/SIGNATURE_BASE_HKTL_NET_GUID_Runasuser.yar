import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Runasuser : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "ead7819a-1397-5953-888f-2176e4041375"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/atthacks/RunAsUser"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1668-L1682"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "585db3eecb3bb91d594c1929c4790acbde8d1c44ae30de2410ef98796c297470"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "9dff282c-93b9-4063-bf8a-b6798371d35a" ascii wide
		$typelibguid0up = "9DFF282C-93B9-4063-BF8A-B6798371D35A" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}