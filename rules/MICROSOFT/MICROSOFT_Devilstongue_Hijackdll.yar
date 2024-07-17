rule MICROSOFT_Devilstongue_Hijackdll : FILE
{
	meta:
		description = "Detects SOURGUM's DevilsTongue hijack DLL"
		author = "Microsoft Threat Intelligence Center (MSTIC)"
		id = "b5de2a8c-e0c8-5c8c-bb65-aee5701b4bb3"
		date = "2021-07-15"
		modified = "2022-07-07"
		reference = "https://www.microsoft.com/security/blog/2021/07/15/protecting-customers-from-a-private-sector-offensive-actor-using-0-day-exploits-and-devilstongue-malware/"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/DevilsTongue_HijackDll.yar#L2-L45"
		license_url = "N/A"
		logic_hash = "d1c01df74a00672bb8229d5433314d7cfa49ab22565e6cf78a4b6b2884dbd299"
		score = 75
		quality = 80
		tags = "FILE"

	strings:
		$str1 = "windows.old\\windows" wide
		$str2 = "NtQueryInformationThread"
		$str3 = "dbgHelp.dll" wide
		$str4 = "StackWalk64"
		$str5 = "ConvertSidToStringSidW"
		$str6 = "S-1-5-18" wide
		$str7 = "SMNew.dll"
		$code1 = {B8 FF 15 00 00 66 39 41 FA 74 06 80 79 FB E8}
		$code2 = {44 8B C0 B8 B5 81 4E 1B 41 F7 E8 C1 FA 05 8B CA C1 E9 1F 03 D1 69 CA 2C 01 00 00 44 2B C1 45 85 C0 7E 19}

	condition:
		filesize <800KB and uint16(0)==0x5A4D and (pe.characteristics&pe.DLL) and (4 of them or ($code1 and $code2) or (pe.imphash()=="9a964e810949704ff7b4a393d9adda60"))
}