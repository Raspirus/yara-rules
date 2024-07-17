import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Tellmeyoursecrets : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "b00c353b-0446-5faa-87e5-0a7ba6ec2286"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/0xbadjuju/TellMeYourSecrets"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2983-L2997"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "cabb37be30a62ef6055e6b6a8f5cd1b9f51b231d254419a94aedd5ddfb992376"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "9b448062-7219-4d82-9a0a-e784c4b3aa27" ascii wide
		$typelibguid0up = "9B448062-7219-4D82-9A0A-E784C4B3AA27" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}