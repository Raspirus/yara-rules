import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharptask : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "2cdd1a15-c70c-5eea-b5a7-8b4a445b9323"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/jnqpblc/SharpTask"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L990-L1004"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8c6fae49accf763101ce0afc6c1ffd07740fbc68105f99059fac4f7ba0c8846c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "13e90a4d-bf7a-4d5a-9979-8b113e3166be" ascii wide
		$typelibguid0up = "13E90A4D-BF7A-4D5A-9979-8B113E3166BE" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}