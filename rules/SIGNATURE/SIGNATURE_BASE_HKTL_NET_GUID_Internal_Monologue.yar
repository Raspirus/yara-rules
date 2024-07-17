rule SIGNATURE_BASE_HKTL_NET_GUID_Internal_Monologue : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "ce2773a2-b0b7-560e-ba21-3f018ddcacb3"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/eladshamir/Internal-Monologue"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L808-L824"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5de43de183553732e48e41d17f441008f0637610d4c15f7f2012437b70750c2c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "0c0333db-8f00-4b68-b1db-18a9cacc1486" ascii wide
		$typelibguid0up = "0C0333DB-8F00-4B68-B1DB-18A9CACC1486" ascii wide
		$typelibguid1lo = "84701ace-c584-4886-a3cf-76c57f6e801a" ascii wide
		$typelibguid1up = "84701ACE-C584-4886-A3CF-76C57F6E801A" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}