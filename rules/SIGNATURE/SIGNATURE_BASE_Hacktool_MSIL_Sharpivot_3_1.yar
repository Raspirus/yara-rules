import "pe"


import "pe"


import "pe"


import "pe"


rule SIGNATURE_BASE_Hacktool_MSIL_Sharpivot_3_1 : FILE
{
	meta:
		description = "This rule looks for .NET PE files that have the strings of various method names in the SharPivot code."
		author = "FireEye"
		id = "956ba026-c2fa-55fd-be53-0cfaa345f27a"
		date = "2024-05-25"
		modified = "2024-05-25"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_fireeye_redteam_tools.yar#L1145-L1174"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "e4efa759d425e2f26fbc29943a30f5bd"
		logic_hash = "f51ac9637f47a98beee1b3c37b594e292aab0e1d3f9e49c41b1f3c3ce02e17de"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$msil = "_CorExeMain" ascii wide
		$str1 = "SharPivot" ascii wide
		$str2 = "ParseArgs" ascii wide
		$str3 = "GenRandomString" ascii wide
		$str4 = "ScheduledTaskExists" ascii wide
		$str5 = "ServiceExists" ascii wide
		$str6 = "lpPassword" ascii wide
		$str7 = "execute" ascii wide
		$str8 = "WinRM" ascii wide
		$str9 = "SchtaskMod" ascii wide
		$str10 = "PoisonHandler" ascii wide
		$str11 = "SCShell" ascii wide
		$str12 = "SchtaskMod" ascii wide
		$str13 = "ServiceHijack" ascii wide
		$str14 = "ServiceHijack" ascii wide
		$str15 = "commandArg" ascii wide
		$str16 = "payloadPath" ascii wide
		$str17 = "Schtask" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and $msil and all of ($str*)
}