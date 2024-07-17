rule SIGNATURE_BASE_HKTL_NET_GUID_Offensivecsharp : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "339f6858-6076-5320-ba5f-2903e642ea42"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/diljith369/OffensiveCSharp"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L706-L742"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8b3f8652b88b353d4fc162f93b373d5beeaaca1b1ebbeaef07a46d859aef4c12"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "6c3fbc65-b673-40f0-b1ac-20636df01a85" ascii wide
		$typelibguid0up = "6C3FBC65-B673-40F0-B1AC-20636DF01A85" ascii wide
		$typelibguid1lo = "2bad9d69-ada9-4f1e-b838-9567e1503e93" ascii wide
		$typelibguid1up = "2BAD9D69-ADA9-4F1E-B838-9567E1503E93" ascii wide
		$typelibguid2lo = "512015de-a70f-4887-8eae-e500fd2898ab" ascii wide
		$typelibguid2up = "512015DE-A70F-4887-8EAE-E500FD2898AB" ascii wide
		$typelibguid3lo = "1ee4188c-24ac-4478-b892-36b1029a13b3" ascii wide
		$typelibguid3up = "1EE4188C-24AC-4478-B892-36B1029A13B3" ascii wide
		$typelibguid4lo = "5c6b7361-f9ab-41dc-bfa0-ed5d4b0032a8" ascii wide
		$typelibguid4up = "5C6B7361-F9AB-41DC-BFA0-ED5D4B0032A8" ascii wide
		$typelibguid5lo = "048a6559-d4d3-4ad8-af0f-b7f72b212e90" ascii wide
		$typelibguid5up = "048A6559-D4D3-4AD8-AF0F-B7F72B212E90" ascii wide
		$typelibguid6lo = "3412fbe9-19d3-41d8-9ad2-6461fcb394dc" ascii wide
		$typelibguid6up = "3412FBE9-19D3-41D8-9AD2-6461FCB394DC" ascii wide
		$typelibguid7lo = "9ea4e0dc-9723-4d93-85bb-a4fcab0ad210" ascii wide
		$typelibguid7up = "9EA4E0DC-9723-4D93-85BB-A4FCAB0AD210" ascii wide
		$typelibguid8lo = "6d2b239c-ba1e-43ec-8334-d67d52b77181" ascii wide
		$typelibguid8up = "6D2B239C-BA1E-43EC-8334-D67D52B77181" ascii wide
		$typelibguid9lo = "42e8b9e1-0cf4-46ae-b573-9d0563e41238" ascii wide
		$typelibguid9up = "42E8B9E1-0CF4-46AE-B573-9D0563E41238" ascii wide
		$typelibguid10lo = "0d15e0e3-bcfd-4a85-adcd-0e751dab4dd6" ascii wide
		$typelibguid10up = "0D15E0E3-BCFD-4A85-ADCD-0E751DAB4DD6" ascii wide
		$typelibguid11lo = "644dfd1a-fda5-4948-83c2-8d3b5eda143a" ascii wide
		$typelibguid11up = "644DFD1A-FDA5-4948-83C2-8D3B5EDA143A" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}