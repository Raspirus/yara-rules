import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Plasmarat : FILE
{
	meta:
		description = "Detects VB.NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "13362cba-f9b2-50c8-95cc-504e585bdd42"
		date = "2020-12-30"
		modified = "2023-04-06"
		reference = "https://github.com/mwsrc/PlasmaRAT"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4389-L4405"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4474f0c9d76a6ec1dd754b0b9ba0bcedce3f82148ecddcdcc4d040220c407788"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "b8a2147c-074c-46e1-bb99-c8431a6546ce" ascii wide
		$typelibguid0up = "B8A2147C-074C-46E1-BB99-C8431A6546CE" ascii wide
		$typelibguid1lo = "0fcfde33-213f-4fb6-ac15-efb20393d4f3" ascii wide
		$typelibguid1up = "0FCFDE33-213F-4FB6-AC15-EFB20393D4F3" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}