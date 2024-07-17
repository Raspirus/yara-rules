rule SIGNATURE_BASE_HKTL_NET_GUID_Privilege_Escalation : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "28615807-6637-57fc-ba56-efc64b041b80"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/Mrakovic-ORG/Privilege_Escalation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1568-L1582"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1fd2eed72a4971f494fcb924b77edb6ab49b8bde400eb2785df00b9b867692d0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "ed54b904-5645-4830-8e68-52fd9ecbb2eb" ascii wide
		$typelibguid0up = "ED54B904-5645-4830-8E68-52FD9ECBB2EB" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}