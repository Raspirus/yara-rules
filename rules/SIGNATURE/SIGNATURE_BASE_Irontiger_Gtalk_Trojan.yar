rule SIGNATURE_BASE_Irontiger_Gtalk_Trojan : FILE
{
	meta:
		description = "Iron Tiger Malware - GTalk Trojan"
		author = "Cyber Safety Solutions, Trend Micro"
		id = "3d72660b-c470-5e63-a83d-990d3c5a696c"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "http://goo.gl/T5fSJC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_irontiger_trendmicro.yar#L121-L135"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "9b6139d34ad91db2e418668be9ca947442ff614a241f0c1aa61f8334af5421c0"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$str1 = "gtalklite.com" wide ascii
		$str2 = "computer=%s&lanip=%s&uid=%s&os=%s&data=%s" wide ascii
		$str3 = "D13idmAdm" wide ascii
		$str4 = "Error: PeekNamedPipe failed with %i" wide ascii

	condition:
		uint16(0)==0x5a4d and (2 of ($str*))
}