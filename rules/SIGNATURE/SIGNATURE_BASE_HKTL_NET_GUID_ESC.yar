rule SIGNATURE_BASE_HKTL_NET_GUID_ESC : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "a57c47e8-62bf-5425-9735-35a3e3a0c218"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/NetSPI/ESC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L940-L956"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ff959136f219b082dd9b601dbf2fea41265ce08a4cf57e368b2b4ac1f09ea698"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "06260ce5-61f4-4b81-ad83-7d01c3b37921" ascii wide
		$typelibguid0up = "06260CE5-61F4-4B81-AD83-7D01C3B37921" ascii wide
		$typelibguid1lo = "87fc7ede-4dae-4f00-ac77-9c40803e8248" ascii wide
		$typelibguid1up = "87FC7EDE-4DAE-4F00-AC77-9C40803E8248" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}