import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Porttran : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "844e58a2-54f5-51e8-8176-6a478a136603"
		date = "2020-12-29"
		modified = "2023-04-06"
		reference = "https://github.com/k8gege/PortTran"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4314-L4330"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "9dda69710b7ff29e34181d694a4922f0da27e1959dd72031ac630a4851a48c62"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "3a074374-77e8-4312-8746-37f3cb00e82c" ascii wide
		$typelibguid0up = "3A074374-77E8-4312-8746-37F3CB00E82C" ascii wide
		$typelibguid1lo = "67a73bac-f59d-4227-9220-e20a2ef42782" ascii wide
		$typelibguid1up = "67A73BAC-F59D-4227-9220-E20A2EF42782" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}