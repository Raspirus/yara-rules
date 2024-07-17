import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_DLL_Injector : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "301e70f4-89ed-539c-b7f3-9fc6ae1393b3"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/tmthrgd/DLL-Injector"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1829-L1845"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "45f63db2fbb807ecab8ebc91bc3ba781f145c60d8e84afd7ea07c57d5aa7bb41"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "4581a449-7d20-4c59-8da2-7fd830f1fd5e" ascii wide
		$typelibguid0up = "4581A449-7D20-4C59-8DA2-7FD830F1FD5E" ascii wide
		$typelibguid1lo = "05f4b238-25ce-40dc-a890-d5bbb8642ee4" ascii wide
		$typelibguid1up = "05F4B238-25CE-40DC-A890-D5BBB8642EE4" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}