rule SIGNATURE_BASE_SUSP_SFX_Cmd : FILE
{
	meta:
		description = "Detects suspicious SFX as used by Gamaredon group"
		author = "Florian Roth (Nextron Systems)"
		id = "87e75fe6-c2d7-5cb4-9432-7c37dbfe94b8"
		date = "2018-09-27"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_suspicious_strings.yar#L316-L328"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "592de6a2165396c4ae8f494e26e56d0a759903b51167b1531b791897dce66868"
		score = 65
		quality = 85
		tags = "FILE"
		hash1 = "965129e5d0c439df97624347534bc24168935e7a71b9ff950c86faae3baec403"

	strings:
		$s1 = /RunProgram=\"hidcon:[a-zA-Z0-9]{1,16}.cmd/ fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and 1 of them
}