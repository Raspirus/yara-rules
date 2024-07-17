import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Grouper2 : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "a9cd9a16-b2a5-5d15-af89-7a8d0f1835bb"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/l0ss/Grouper2/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2949-L2963"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0c1909e40b587d86766ff393cc056352ffaf40f2b56c3a1217b1526cc42e4eb7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "5decaea3-2610-4065-99dc-65b9b4ba6ccd" ascii wide
		$typelibguid0up = "5DECAEA3-2610-4065-99DC-65B9B4BA6CCD" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}