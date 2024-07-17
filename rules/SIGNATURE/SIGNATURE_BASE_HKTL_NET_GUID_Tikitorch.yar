import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Tikitorch : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "354ee690-a0d0-5cc5-a73b-53b916ed0169"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/rasta-mouse/TikiTorch"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3328-L3354"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "072129fea5e40b2fcbf13156ccf8c5a05e343b98f02dc7140261f6534a5b9e4e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "806c6c72-4adc-43d9-b028-6872fa48d334" ascii wide
		$typelibguid0up = "806C6C72-4ADC-43D9-B028-6872FA48D334" ascii wide
		$typelibguid1lo = "2ef9d8f7-6b77-4b75-822b-6a53a922c30f" ascii wide
		$typelibguid1up = "2EF9D8F7-6B77-4B75-822B-6A53A922C30F" ascii wide
		$typelibguid2lo = "8f5f3a95-f05c-4dce-8bc3-d0a0d4153db6" ascii wide
		$typelibguid2up = "8F5F3A95-F05C-4DCE-8BC3-D0A0D4153DB6" ascii wide
		$typelibguid3lo = "1f707405-9708-4a34-a809-2c62b84d4f0a" ascii wide
		$typelibguid3up = "1F707405-9708-4A34-A809-2C62B84D4F0A" ascii wide
		$typelibguid4lo = "97421325-b6d8-49e5-adf0-e2126abc17ee" ascii wide
		$typelibguid4up = "97421325-B6D8-49E5-ADF0-E2126ABC17EE" ascii wide
		$typelibguid5lo = "06c247da-e2e1-47f3-bc3c-da0838a6df1f" ascii wide
		$typelibguid5up = "06C247DA-E2E1-47F3-BC3C-DA0838A6DF1F" ascii wide
		$typelibguid6lo = "fc700ac6-5182-421f-8853-0ad18cdbeb39" ascii wide
		$typelibguid6up = "FC700AC6-5182-421F-8853-0AD18CDBEB39" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}