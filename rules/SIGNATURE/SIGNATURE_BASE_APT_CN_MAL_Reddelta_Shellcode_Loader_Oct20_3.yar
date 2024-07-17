rule SIGNATURE_BASE_APT_CN_MAL_Reddelta_Shellcode_Loader_Oct20_3 : FILE
{
	meta:
		description = "Detects Red Delta samples"
		author = "Florian Roth (Nextron Systems)"
		id = "b52836bb-cdef-5416-a8e1-72d0b2298546"
		date = "2020-10-14"
		modified = "2022-12-21"
		reference = "https://twitter.com/JAMESWT_MHT/status/1316387482708119556"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_cn_reddelta.yar#L59-L78"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "64402f6265f23abf7d6a711aa888c89386c1a754f12286b0efe5fd5d81f15b01"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "740992d40b84b10aa9640214a4a490e989ea7b869cea27dbbdef544bb33b1048"

	strings:
		$s1 = "Taskschd.dll" ascii fullword
		$s2 = "AddTaskPlanDllVerson.dll" ascii fullword
		$s3 = "\\FlashUpdate.exe" ascii
		$s4 = "D:\\Project\\FBIRedTeam" ascii fullword
		$s5 = "Error %s:%d, ErrorCode: %x" ascii fullword

	condition:
		uint16(0)==0x5a4d and filesize <400KB and 4 of them
}