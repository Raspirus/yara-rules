
rule SIGNATURE_BASE_APT_Webshell_AUS_Jscript_3 : FILE
{
	meta:
		description = "Detetcs a webshell involved in the Australian Parliament House network compromise"
		author = "Florian Roth (Nextron Systems)"
		id = "ff7e780b-ccf9-53b6-b741-f04a8cbaf580"
		date = "2019-02-18"
		modified = "2023-12-05"
		reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_aus_parl_compromise.yar#L40-L53"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e144e555dd80e15ac9072a645e629a86ca1a6b52949d236ec3daedbf06bd6718"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "7ac6f973f7fccf8c3d58d766dec4ab7eb6867a487aa71bc11d5f05da9322582d"

	strings:
		$s1 = "<%@ Page Language=\"Jscript\" validateRequest=\"false\"%><%try{eval(System.Text.Encoding.UTF8.GetString(Convert.FromBase64String" ascii
		$s2 = ".Item[\"[password]\"])),\"unsafe\");}" ascii

	condition:
		uint16(0)==0x6568 and filesize <1KB and all of them
}