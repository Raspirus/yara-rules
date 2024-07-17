
rule SIGNATURE_BASE_Irontiger_EFH3_Encoder : FILE
{
	meta:
		description = "Iron Tiger EFH3 Encoder"
		author = "Cyber Safety Solutions, Trend Micro"
		id = "ec30782e-8fe9-5843-9db4-5a3c477b7f25"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "http://goo.gl/T5fSJC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_irontiger_trendmicro.yar#L86-L99"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e620222f815a6c915e372c11d28c480179fd2abdb139ed6984ca5a7a61b8088c"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$str1 = "EFH3 [HEX] [SRCFILE] [DSTFILE]" wide ascii
		$str2 = "123.EXE 123.EFH" wide ascii
		$str3 = "ENCODER: b[i]: = " wide ascii

	condition:
		uint16(0)==0x5a4d and ( any of ($str*))
}