import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Psbypassclm : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "dad6729f-3d96-5d2d-b72c-a96d1a3eae74"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/padovah4ck/PSByPassCLM"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L218-L232"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "45538484f473f2940344fb89181e309b9925619ea6cf7e66a106cea9e9c6f281"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "46034038-0113-4d75-81fd-eb3b483f2662" ascii wide
		$typelibguid0up = "46034038-0113-4D75-81FD-EB3B483F2662" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}