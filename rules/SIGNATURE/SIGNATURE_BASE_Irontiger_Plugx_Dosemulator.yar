rule SIGNATURE_BASE_Irontiger_Plugx_Dosemulator : FILE
{
	meta:
		description = "Iron Tiger Malware - PlugX DosEmulator"
		author = "Cyber Safety Solutions, Trend Micro - modified by Florian Roth"
		id = "e601d91d-49e6-5fe9-b70b-fb1fb6c4f059"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "http://goo.gl/T5fSJC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_irontiger_trendmicro.yar#L171-L185"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "502adc142b0f7a2980b4b851f2360086cec855b5e9851a6e9afbaba1846d11ed"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$str1 = "Dos Emluator Ver" wide ascii
		$str2 = "\\PIPE\\FASTDOS" wide ascii
		$str3 = "FastDos.cpp" wide ascii
		$str4 = "fail,error code = %d." wide ascii

	condition:
		uint16(0)==0x5a4d and 2 of ($str*)
}