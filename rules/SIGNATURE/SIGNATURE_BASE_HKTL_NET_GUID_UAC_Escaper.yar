import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_UAC_Escaper : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "ea95ff3c-0cbb-5230-b5e4-bd8b2ff975eb"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/NYAN-x-CAT/UAC-Escaper"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L606-L620"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b6e293a6c1589b527ac4d72ccc5609b6899a8ff69009d30e9a93b046484564c8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "95359279-5cfa-46f6-b400-e80542a7336a" ascii wide
		$typelibguid0up = "95359279-5CFA-46F6-B400-E80542A7336A" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}