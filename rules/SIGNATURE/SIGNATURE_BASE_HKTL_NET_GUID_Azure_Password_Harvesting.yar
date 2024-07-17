import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Azure_Password_Harvesting : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "681cf9da-d664-5402-b7ac-eb2cfad85da9"
		date = "2020-12-21"
		modified = "2023-04-06"
		reference = "https://github.com/guardicore/azure_password_harvesting"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2749-L2763"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4b42d3318af410952f96ede0959363f33e75ce0644c58c1de85165e0acbbfcdd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "7ad1ff2d-32ac-4c54-b615-9bb164160dac" ascii wide
		$typelibguid0up = "7AD1FF2D-32AC-4C54-B615-9BB164160DAC" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}