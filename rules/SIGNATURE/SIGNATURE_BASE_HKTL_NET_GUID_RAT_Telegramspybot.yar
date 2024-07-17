rule SIGNATURE_BASE_HKTL_NET_GUID_RAT_Telegramspybot : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "57d22201-a051-5040-927c-30da3fc684fd"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/SebastianEPH/RAT.TelegramSpyBot"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2063-L2077"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ed661d6513df3a3e8558912f96f86bff55214f9ba6426085af8458a5c9c62d1f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "8653fa88-9655-440e-b534-26c3c760a0d3" ascii wide
		$typelibguid0up = "8653FA88-9655-440E-B534-26C3C760A0D3" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}