import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Memevm : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "c98d84d5-4b0a-53df-b8d4-0b360930eb0c"
		date = "2021-01-21"
		modified = "2023-04-06"
		reference = "https://github.com/TobitoFatitoRE/MemeVM"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4673-L4691"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7430b5d82012fc63459d97a21d93260ccda7ac8249bf4b56384e3b0ab6b5548a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "ef18f7f2-1f03-481c-98f9-4a18a2f12c11" ascii wide
		$typelibguid0up = "EF18F7F2-1F03-481C-98F9-4A18A2F12C11" ascii wide
		$typelibguid1lo = "77b2c83b-ca34-4738-9384-c52f0121647c" ascii wide
		$typelibguid1up = "77B2C83B-CA34-4738-9384-C52F0121647C" ascii wide
		$typelibguid2lo = "14d5d12e-9a32-4516-904e-df3393626317" ascii wide
		$typelibguid2up = "14D5D12E-9A32-4516-904E-DF3393626317" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}