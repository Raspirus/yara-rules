
rule SIGNATURE_BASE_SUSP_Scheduled_Task_Bigsize : FILE
{
	meta:
		description = "Detects suspiciously big scheduled task XML file as seen in combination with embedded base64 encoded PowerShell code"
		author = "Florian Roth (Nextron Systems)"
		id = "61b07b30-1058-5a53-99e7-2c48ec9d23b5"
		date = "2018-12-06"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/generic_anomalies.yar#L424-L440"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "dcc06261b1ea39c587d8bcefbb8e85e6b9016da01bf66c2eefe5bd7bbdfc6968"
		score = 65
		quality = 85
		tags = "FILE"

	strings:
		$a0 = "<Task version=" ascii wide
		$a1 = "xmlns=\"http://schemas.microsoft.com/windows/" ascii wide
		$fp1 = "</Counter><Counter>" wide
		$fp2 = "Office Feature Updates Logon" wide
		$fp3 = "Microsoft Shared" fullword wide

	condition:
		uint16(0)==0xfeff and filesize >20KB and all of ($a*) and not 1 of ($fp*)
}