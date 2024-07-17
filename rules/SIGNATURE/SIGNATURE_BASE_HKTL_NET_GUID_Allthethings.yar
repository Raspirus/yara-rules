import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Allthethings : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "c35160cb-ad31-5195-a7c6-0af91a58737d"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/johnjohnsp1/AllTheThings"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1901-L1915"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "09836251d75327ef547451024ffed76de8cf41ce027fbf40db0cac44f74d46d5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "0547ff40-5255-42a2-beb7-2ff0dbf7d3ba" ascii wide
		$typelibguid0up = "0547FF40-5255-42A2-BEB7-2FF0DBF7D3BA" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}