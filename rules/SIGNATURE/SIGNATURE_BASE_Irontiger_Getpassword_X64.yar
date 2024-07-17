rule SIGNATURE_BASE_Irontiger_Getpassword_X64 : FILE
{
	meta:
		description = "Iron Tiger Malware - GetPassword x64"
		author = "Cyber Safety Solutions, Trend Micro"
		id = "8f55b23f-52fd-5106-9112-6cffa97269ab"
		date = "2023-01-06"
		modified = "2023-12-05"
		reference = "http://goo.gl/T5fSJC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_irontiger_trendmicro.yar#L101-L119"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "2adabc629fcd4bc89a015874376daf51b2a367bb13ec25e917e5d899080d8a74"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$str1 = "(LUID ERROR)" wide ascii
		$str2 = "Users\\K8team\\Desktop\\GetPassword" wide ascii
		$str3 = "Debug x64\\GetPassword.pdb" ascii
		$bla1 = "Authentication Package:" wide ascii
		$bla2 = "Authentication Domain:" wide ascii
		$bla3 = "* Password:" wide ascii
		$bla4 = "Primary User:" wide ascii

	condition:
		uint16(0)==0x5a4d and (( any of ($str*)) or ( all of ($bla*)))
}