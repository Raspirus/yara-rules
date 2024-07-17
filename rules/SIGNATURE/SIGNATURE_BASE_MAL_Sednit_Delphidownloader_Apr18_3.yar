
rule SIGNATURE_BASE_MAL_Sednit_Delphidownloader_Apr18_3 : FILE
{
	meta:
		description = "Detects malware from Sednit Delphi Downloader report"
		author = "Florian Roth (Nextron Systems)"
		id = "2200fbdc-3600-51d4-a273-dc7fd4127c05"
		date = "2018-04-24"
		modified = "2023-01-06"
		reference = "https://www.welivesecurity.com/2018/04/24/sednit-update-analysis-zebrocy/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_sednit_delphidownloader.yar#L40-L62"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "20446692842ec9481f34dd976f6b309515c33159653f9988a59335d2f04e4138"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "ecb835d03060db1ea3496ceca2d79d7c4c6c671c9907e0b0e73bf8d3371fa931"
		hash2 = "e355a327479dcc4e71a38f70450af02411125c5f101ba262e8df99f9f0fef7b6"

	strings:
		$ = "Processor Level: " fullword ascii
		$ = "CONNECTION ERROR" fullword ascii
		$ = "FILE_EXECUTE_AND_KILL_MYSELF" ascii
		$ = "-KILL_PROCESS-" ascii
		$ = "-FILE_EXECUTE-" ascii
		$ = "-DOWNLOAD_ERROR-" ascii
		$ = "CMD_EXECUTE" fullword ascii
		$ = "\\Interface\\Office\\{31E12FE8-937F-1E32-871D-B1C9AOEF4D4}\\" ascii
		$ = "Mozilla/3.0 (compatible; Indy Library)" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and 3 of them
}