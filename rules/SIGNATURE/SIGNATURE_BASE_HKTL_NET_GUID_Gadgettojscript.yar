import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Gadgettojscript : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "e296795f-d006-52a9-92c4-fb60c930564b"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/med0x2e/GadgetToJScript"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L572-L588"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "07ba9b4c303c12a74a13b28dddd4b1118cc30335bf9e76d8146224242619e87d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "af9c62a1-f8d2-4be0-b019-0a7873e81ea9" ascii wide
		$typelibguid0up = "AF9C62A1-F8D2-4BE0-B019-0A7873E81EA9" ascii wide
		$typelibguid1lo = "b2b3adb0-1669-4b94-86cb-6dd682ddbea3" ascii wide
		$typelibguid1up = "B2B3ADB0-1669-4B94-86CB-6DD682DDBEA3" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}