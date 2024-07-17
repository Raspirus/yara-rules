rule SIGNATURE_BASE_HKTL_NET_GUID_Stormkitty : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "09d66661-5b67-5846-9bea-ec682afb62cf"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/LimerBoy/StormKitty"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1634-L1650"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "aef8e28d9eb5f6cd6fdc0a8bf60f00b99a920197a0ecaa75baca5a8570973ab7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "a16abbb4-985b-4db2-a80c-21268b26c73d" ascii wide
		$typelibguid0up = "A16ABBB4-985B-4DB2-A80C-21268B26C73D" ascii wide
		$typelibguid1lo = "98075331-1f86-48c8-ae29-29da39a8f98b" ascii wide
		$typelibguid1up = "98075331-1F86-48C8-AE29-29DA39A8F98B" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}