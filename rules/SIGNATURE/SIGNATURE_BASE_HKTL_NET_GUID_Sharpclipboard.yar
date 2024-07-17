import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpclipboard : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "fd1b7786-8853-5858-ab03-da350e44f738"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/slyd0g/SharpClipboard"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3537-L3551"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f935b91fcbf982af9e67f90fe1ce9086217066dd2127dea17c92db5c185b91b9"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "97484211-4726-4129-86aa-ae01d17690be" ascii wide
		$typelibguid0up = "97484211-4726-4129-86AA-AE01D17690BE" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}