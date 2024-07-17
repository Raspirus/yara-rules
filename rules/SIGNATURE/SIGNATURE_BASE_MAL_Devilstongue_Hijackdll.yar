import "pe"


rule SIGNATURE_BASE_MAL_Devilstongue_Hijackdll : FILE
{
	meta:
		description = "Detects SOURGUM's DevilsTongue hijack DLL"
		author = "Microsoft Threat Intelligence Center (MSTIC)"
		id = "390b8b73-6740-513d-8c70-c9002be0ce69"
		date = "2021-07-15"
		modified = "2023-12-05"
		reference = "https://www.microsoft.com/security/blog/2021/07/15/protecting-customers-from-a-private-sector-offensive-actor-using-0-day-exploits-and-devilstongue-malware/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_candiru.yar#L3-L47"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4ad58a77f9ab5fa078dc40f3ec1d0b0180f25ff3ea304a3c85889df29739e0f5"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$str1 = "windows.old\\windows" wide
		$str2 = "NtQueryInformationThread"
		$str3 = "dbgHelp.dll" wide
		$str4 = "StackWalk64"
		$str5 = "ConvertSidToStringSidW"
		$str6 = "S-1-5-18" wide
		$str7 = "SMNew.dll"
		$code1 = { B8 FF 15 00 00 66 39 41 FA 74 06 80 79 FB E8 }
		$code2 = { 44 8B C0 B8 B5 81 4E 1B 41 F7 E8 C1 FA 05 8B CA C1 E9 1F 03 D1 69 CA 2C 01 00 00 44 2B C1 45 85 C0 7E 19 }

	condition:
		filesize <800KB and uint16(0)==0x5A4D and (pe.characteristics&pe.DLL) and (4 of them or ($code1 and $code2) or pe.imphash()=="9a964e810949704ff7b4a393d9adda60")
}