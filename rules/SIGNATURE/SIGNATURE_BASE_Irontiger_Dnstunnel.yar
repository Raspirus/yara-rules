
rule SIGNATURE_BASE_Irontiger_Dnstunnel : FILE
{
	meta:
		description = "This rule detects a dns tunnel tool used in Operation Iron Tiger"
		author = "Cyber Safety Solutions, Trend Micro"
		id = "7f24d3dd-4301-5b12-8262-4cc5f6578a4b"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "http://goo.gl/T5fSJC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_irontiger_trendmicro.yar#L65-L84"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "84b7dec3a89fe309149c7a3141279755adafbf793521c7b9b4031827f1020d7d"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$str1 = "\\DnsTunClient\\" wide ascii
		$str2 = "\\t-DNSTunnel\\" wide ascii
		$str3 = "xssok.blogspot" wide ascii
		$str4 = "dnstunclient" wide ascii
		$mistake1 = "because of error, can not analysis" wide ascii
		$mistake2 = "can not deal witn the error" wide ascii
		$mistake3 = "the other retun one RST" wide ascii
		$mistake4 = "Coversation produce one error" wide ascii
		$mistake5 = "Program try to use the have deleted the buffer" wide ascii

	condition:
		( uint16(0)==0x5a4d) and (( any of ($str*)) or ( any of ($mistake*)))
}