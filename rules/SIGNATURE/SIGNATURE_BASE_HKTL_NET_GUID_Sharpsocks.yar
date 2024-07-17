rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpsocks : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "343061d9-e24e-5d49-939f-b94c295b17ac"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/nettitude/SharpSocks"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3989-L4005"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ef582f9ba7b49795886c69a48cf9ac11e86fb99c19463f0770f3e9c1e3e2e0c6"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "2f43992e-5703-4420-ad0b-17cb7d89c956" ascii wide
		$typelibguid0up = "2F43992E-5703-4420-AD0B-17CB7D89C956" ascii wide
		$typelibguid1lo = "86d10a34-c374-4de4-8e12-490e5e65ddff" ascii wide
		$typelibguid1up = "86D10A34-C374-4DE4-8E12-490E5E65DDFF" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}