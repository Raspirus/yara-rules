
rule SIGNATURE_BASE_Irontiger_Plugx_Server : FILE
{
	meta:
		description = "Iron Tiger Malware - PlugX Server"
		author = "Cyber Safety Solutions, Trend Micro"
		id = "38011a23-3ed7-5f58-a814-2551526b27f3"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "http://goo.gl/T5fSJC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_irontiger_trendmicro.yar#L205-L225"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "14b3f3b75cf6d042934e6916c99fe41d54065d59be6eb30b3cecc799997ac9d4"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$str1 = "\\UnitFrmManagerKeyLog.pas" wide ascii
		$str2 = "\\UnitFrmManagerRegister.pas" wide ascii
		$str3 = "Input Name..." wide ascii
		$str4 = "New Value#" wide ascii
		$str5 = "TThreadRControl.Execute SEH!!!" wide ascii
		$str6 = "\\UnitFrmRControl.pas" wide ascii
		$str7 = "OnSocket(event is error)!" wide ascii
		$str8 = "Make 3F Version Ok!!!" wide ascii
		$str9 = "PELEASE DO NOT CHANGE THE DOCAMENT" wide ascii
		$str10 = "Press [Ok] Continue Run, Press [Cancel] Exit" wide ascii

	condition:
		uint16(0)==0x5a4d and (2 of ($str*))
}