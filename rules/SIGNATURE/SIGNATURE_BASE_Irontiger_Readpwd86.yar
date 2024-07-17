rule SIGNATURE_BASE_Irontiger_Readpwd86 : FILE
{
	meta:
		description = "Iron Tiger Malware - ReadPWD86"
		author = "Cyber Safety Solutions, Trend Micro"
		id = "5db832be-4b8e-536f-8db7-a215a90284e2"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "http://goo.gl/T5fSJC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_irontiger_trendmicro.yar#L227-L240"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c188b033aee6b7e811c125af545aa7851cd45ba02e057ee93967fa98d1c13947"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$str1 = "Fail To Load LSASRV" wide ascii
		$str2 = "Fail To Search LSASS Data" wide ascii
		$str3 = "User Principal" wide ascii

	condition:
		uint16(0)==0x5a4d and ( all of ($str*))
}