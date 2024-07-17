rule SIGNATURE_BASE_MAL_Sharpshooter_Excel4 : FILE
{
	meta:
		description = "Detects Excel documents weaponized with Sharpshooter"
		author = "John Lambert, Florian Roth"
		id = "a79e3afe-e8f9-5e56-a131-bb1b346df471"
		date = "2020-03-27"
		modified = "2023-12-05"
		reference = "https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/00b5dd7d-51ca-4938-b7b7-483fe0e5933b"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_Excel4Macro_Sharpshooter.yar#L1-L25"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "ccef64586d25ffcb2b28affc1f64319b936175c4911e7841a0e28ee6d6d4a02d"
		logic_hash = "4aec8bb7ec8ce7ebd8228416133ea7eec995864aeec78c11548387d832b5fa65"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$header_docf = { D0 CF 11 E0 }
		$s1 = "Excel 4.0 Macros"
		$f1 = "CreateThread" ascii fullword
		$f2 = "WriteProcessMemory" ascii fullword
		$f3 = "Kernel32" ascii fullword
		$concat = { 00 41 6f 00 08 1e ?? 00 41 6f 00 08 1e ?? 00 41 6f 00 08}

	condition:
		filesize <1000KB and $header_docf at 0 and #concat>10 and $s1 and 2 of ($f*)
}