rule SIGNATURE_BASE_APT_FIN7_EXE_Sample_Aug18_8 : FILE
{
	meta:
		description = "Detects sample from FIN7 report in August 2018"
		author = "Florian Roth (Nextron Systems)"
		id = "1eb9810e-2b50-5a93-925e-073bb17e1e6c"
		date = "2018-08-01"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_fin7.yar#L216-L229"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f15a8dfd3efb094ab73caebe9bffb5735762960445ca421cd49eaa091ecea300"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "d8bda53d7f2f1e4e442a0e1c30a20d6b0ac9c6880947f5dd36f78e4378b20c5c"

	strings:
		$s1 = "GetL3st3rr" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <600KB and all of them
}