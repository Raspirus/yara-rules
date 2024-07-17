rule SIGNATURE_BASE_HKTL_NET_GUID_Keylogger : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "0576756e-26d5-5165-b621-917126a75a38"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/BlackVikingPro/Keylogger"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2339-L2353"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "37cd0615243abc0a2d29220285aabcaa75824ab1bc9b8ab395d90c1851a0159a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "7afbc9bf-32d9-460f-8a30-35e30aa15879" ascii wide
		$typelibguid0up = "7AFBC9BF-32D9-460F-8A30-35E30AA15879" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}