rule SIGNATURE_BASE_HKTL_NET_NAME_Stagestrike : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "e3f9de04-87f6-5b07-b5b0-a26167937fcc"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/RedXRanger/StageStrike"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L807-L820"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "99abc2fee732f27ea94c8ce244dc1742ed01a7753adedd7e80226d1e1c8dee4a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "StageStrike" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}