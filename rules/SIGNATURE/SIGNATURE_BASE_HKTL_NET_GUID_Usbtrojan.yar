import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Usbtrojan : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "d25c9033-13e8-5fc9-8561-f8862cca39b8"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/mashed-potatoes/USBTrojan"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2107-L2121"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8435a9f9fdf1e29010db3f3c1f55c19d616761b0585a232686ed377a6a252297"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "4eee900e-adc5-46a7-8d7d-873fd6aea83e" ascii wide
		$typelibguid0up = "4EEE900E-ADC5-46A7-8D7D-873FD6AEA83E" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}