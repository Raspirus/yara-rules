import "pe"


rule R3C0NST_ATM_CINEO4060_Blackbox : FILE
{
	meta:
		description = "Detects Malware samples for Diebold Nixdorf CINEO 4060 ATMs used in blackboxing attacks across Europe since May 2021"
		author = "Frank Boldewin (@r3c0nst)"
		id = "8fa26e1c-2931-59c8-9cec-20dc6684b8d6"
		date = "2021-05-25"
		modified = "2022-06-21"
		reference = "https://twitter.com/r3c0nst/status/1539036442516660224"
		source_url = "https://github.com/fboldewin/YARA-rules//blob/54e9e6899b258b72074b2b4db6909257683240c2/ATM_CINEO4060_Blackbox.yar#L3-L27"
		license_url = "N/A"
		logic_hash = "80b919d03c1b9a198611994eaf2fafaf8254c73a6f0edb53b2b3eb90ea70d915"
		score = 75
		quality = 90
		tags = "FILE"

	strings:
		$MyAgent1 = "javaagentsdemo/ClassListingTransformer.class" ascii fullword
		$MyAgent2 = "javaagentsdemo/MyUtils.class" ascii fullword
		$MyAgent3 = "javaagentsdemo/SimplestAgent.class" ascii fullword
		$Hook = "### [HookAPI]: Switching context!" fullword ascii
		$Delphi = "Borland\\Delphi\\RTL" fullword ascii
		$WMIHOOK1 = "TPM_SK.DLL" fullword ascii
		$WMIHOOK2 = "GetPCData" fullword ascii
		$WMIHOOK3 = {60 9C A3 E4 2B 41 00 E8 ?? ?? ?? ?? 9D 61 B8 02 00 00 00 C3}
		$TRICK1 = "USERAUTH.DLL" fullword ascii
		$TRICK2 = "GetAllSticksByID" fullword ascii
		$TRICK3 = {6A 06 8B 45 FC 8B 00 B1 4F BA 1C 00 00 00}

	condition:
		( uint16(0)==0x4b50 and filesize <50KB and all of ($MyAgent*)) or ( uint16(0)==0x5A4D and (pe.characteristics&pe.DLL) and $Hook and $Delphi and all of ($WMIHOOK*) or all of ($TRICK*))
}