rule SIGNATURE_BASE_Irontiger_Changeport_Toolkit_Driversinstall : FILE
{
	meta:
		description = "Iron Tiger Malware - Changeport Toolkit driverinstall"
		author = "Cyber Safety Solutions, Trend Micro"
		id = "fde2728b-9a23-5f35-9727-0834a7b403da"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "http://goo.gl/T5fSJC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_irontiger_trendmicro.yar#L15-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "2ae32596da4f98a0ec2556c2cd87fc7a0f85c37ce96c7163664f2e8cc3ec498d"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$str1 = "openmydoor" wide ascii
		$str2 = "Install service error" wide ascii
		$str3 = "start remove service" wide ascii
		$str4 = "NdisVersion" wide ascii

	condition:
		uint16(0)==0x5a4d and (2 of ($str*))
}