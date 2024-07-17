import "pe"


import "pe"


rule SIGNATURE_BASE_HKTL_Shellpop_Tclsh : FILE
{
	meta:
		description = "Detects suspicious TCLsh popshell"
		author = "Tobias Michalski"
		id = "24f6b626-383e-54c9-abd4-bd67c37af937"
		date = "2018-05-18"
		modified = "2023-12-05"
		reference = "https://github.com/0x00-0x00/ShellPop"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L4237-L4249"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "622805e8067f5158d82783971dcf31e8db05f1d52a38bd1ec3e76ddbbd78032b"
		score = 65
		quality = 85
		tags = "FILE"
		hash1 = "9f49d76d70d14bbe639a3c16763d3b4bee92c622ecb1c351cb4ea4371561e133"

	strings:
		$s1 = "{ puts -nonewline $s \"shell>\";flush $s;gets $s c;set e \"exec $c\";if" ascii

	condition:
		filesize <1KB and 1 of them
}