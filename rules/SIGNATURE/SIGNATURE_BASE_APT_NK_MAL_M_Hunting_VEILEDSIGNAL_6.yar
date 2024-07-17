rule SIGNATURE_BASE_APT_NK_MAL_M_Hunting_VEILEDSIGNAL_6 : FILE
{
	meta:
		description = "Detects VEILEDSIGNAL malware"
		author = "Mandiant"
		id = "2cbedbc0-d465-5674-bf9c-9362003eb8d2"
		date = "2023-04-20"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_nk_tradingtech_apr23.yar#L145-L164"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d3b1e5f7a6b73fc4cdc5abe19a412130cde33c2d52c0ad78256b865e018e3794"
		score = 75
		quality = 85
		tags = "FILE"
		disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
		hash1 = "00a43d64f9b5187a1e1f922b99b09b77"

	strings:
		$ss1 = "C:\\Programdata\\" wide
		$ss2 = "devobj.dll" wide fullword
		$ss3 = "msvcr100.dll" wide fullword
		$ss4 = "TpmVscMgrSvr.exe" wide fullword
		$ss5 = "\\Microsoft\\Windows\\TPM" wide fullword
		$ss6 = "CreateFileW" ascii fullword

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and ( uint16( uint32(0x3C)+0x18)==0x010B) and all of them
}