rule SIGNATURE_BASE_Gazer_Logfile_Name_1 : FILE
{
	meta:
		description = "Detects Tura's Gazer malware"
		author = "ESET"
		id = "c10d440f-dc9e-54c8-b329-9f22cba05e86"
		date = "2017-08-30"
		modified = "2023-12-05"
		reference = "https://www.welivesecurity.com/2017/08/30/eset-research-cyberespionage-gazer/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_turla_gazer.yar#L41-L54"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c893ec41884f106329350c079b087e41a5b9f1040ab0892c90c03972d49dc070"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "CVRG72B5.tmp.cvr"
		$s2 = "CVRG1A6B.tmp.cvr"
		$s3 = "CVRG38D9.tmp.cvr"

	condition:
		uint16(0)==0x5a4d and 1 of them
}