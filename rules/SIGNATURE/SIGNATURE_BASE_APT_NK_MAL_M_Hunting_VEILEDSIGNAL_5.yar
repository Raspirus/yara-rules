import "pe"


rule SIGNATURE_BASE_APT_NK_MAL_M_Hunting_VEILEDSIGNAL_5 : FILE
{
	meta:
		description = "Detects VEILEDSIGNAL malware"
		author = "Mandiant"
		id = "7d0718fc-4f1c-5293-8dc4-81a5783fbfb2"
		date = "2023-04-20"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_nk_tradingtech_apr23.yar#L120-L143"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5d43b8198ad224bee8d290dd7031d73f76a7d957a2e3b44d89e7aaf5f2c94c65"
		score = 75
		quality = 85
		tags = "FILE"
		disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
		hash1 = "6727284586ecf528240be21bb6e97f88"

	strings:
		$sb1 = { 48 8D 15 [4] 48 8D 4C 24 4C E8 [4] 85 C0 74 ?? 48 8D 15 [4] 48 8D 4C 24 4C E8 [4] 85 C0 74 ?? 48 8D 15 [4] 48 8D 4C 24 4C E8 [4] 85 C0 74 ?? 48 8D [3] 48 8B CB FF 15 [4] EB }
		$ss1 = "chrome.exe" wide fullword
		$ss2 = "firefox.exe" wide fullword
		$ss3 = "msedge.exe" wide fullword
		$ss4 = "\\\\.\\pipe\\*" ascii fullword
		$ss5 = "FindFirstFileA" ascii fullword
		$ss6 = "Process32FirstW" ascii fullword
		$ss7 = "RtlAdjustPrivilege" ascii fullword
		$ss8 = "GetCurrentProcess" ascii fullword
		$ss9 = "NtWaitForSingleObject" ascii fullword

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and ( uint16( uint32(0x3C)+0x18)==0x020B) and all of them
}