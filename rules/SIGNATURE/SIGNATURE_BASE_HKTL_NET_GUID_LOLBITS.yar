import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_LOLBITS : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "66454ac0-742b-51a3-ac45-1ac9606e8b89"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/Kudaes/LOLBITS"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2323-L2337"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8c60938c037017f5b0ee355aec23fc8b7c629202457edaec01ab5a5ed94dc2f1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "29d09aa4-ea0c-47c2-973c-1d768087d527" ascii wide
		$typelibguid0up = "29D09AA4-EA0C-47C2-973C-1D768087D527" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}