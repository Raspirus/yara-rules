rule SIGNATURE_BASE_VBS_Obfuscated_Mal_Feb18_1 : FILE
{
	meta:
		description = "Detects malicious obfuscated VBS observed in February 2018"
		author = "Florian Roth (Nextron Systems)"
		id = "39ea10e5-9dea-5cc8-8388-15378fcbab60"
		date = "2018-02-12"
		modified = "2023-12-05"
		reference = "https://goo.gl/zPsn83"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_mal_scripts.yar#L133-L155"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0bbd388a3103744df2434956c2b7ac12dacd72f9041b4cc014d31eec4115aedd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "06960cb721609fe5a857fe9ca3696a84baba88d06c20920370ddba1b0952a8ab"
		hash2 = "c5c0e28093e133d03c3806da0061a35776eed47d351e817709d2235b95d3a036"
		hash3 = "e1765a2b10e2ff10235762b9c65e9f5a4b3b47d292933f1a710e241fe0417a74"

	strings:
		$x1 = "A( Array( (1* 2^1 )+" ascii
		$x2 = ".addcode(A( Array(" ascii
		$x3 = "false:AA.send:Execute(AA.responsetext):end" ascii
		$x4 = "& A( Array(  (1* 2^1 )+" ascii
		$s1 = ".SYSTEMTYPE:NEXT:IF (UCASE(" ascii
		$s2 = "A = STR:next:end function" ascii
		$s3 = "&WSCRIPT.SCRIPTFULLNAME&CHR" fullword ascii

	condition:
		filesize <600KB and (1 of ($x*) or 3 of them )
}