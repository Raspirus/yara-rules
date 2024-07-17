rule SIGNATURE_BASE_Irontiger_Changeport_Toolkit_Changeportexe : FILE
{
	meta:
		description = "Iron Tiger Malware - Toolkit ChangePort"
		author = "Cyber Safety Solutions, Trend Micro"
		id = "2ba74413-5f72-560a-8567-1c4bf3357097"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "http://goo.gl/T5fSJC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_irontiger_trendmicro.yar#L31-L46"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b5a5a1cff372d97bfa281d297b6230279cd1526c5df636efe4dec3aa3d923edf"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$str1 = "Unable to alloc the adapter!" wide ascii
		$str2 = "Wait for master fuck" wide ascii
		$str3 = "xx.exe <HOST> <PORT>" wide ascii
		$str4 = "chkroot2007" wide ascii
		$str5 = "Door is bind on %s" wide ascii

	condition:
		uint16(0)==0x5a4d and (2 of ($str*))
}