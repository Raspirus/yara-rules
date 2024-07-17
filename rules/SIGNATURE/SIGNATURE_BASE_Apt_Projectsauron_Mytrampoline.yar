import "pe"

import "math"


rule SIGNATURE_BASE_Apt_Projectsauron_Mytrampoline : FILE
{
	meta:
		description = "Rule to detect ProjectSauron MyTrampoline module"
		author = "Kaspersky Lab"
		id = "b4f2cabf-11da-5fa1-8c23-0a177f8a4741"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_project_sauron.yara#L65-L83"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0bd98815fbf6e82cf477e4f4f98360a4c132b2b21e2e5991f6c10903bd4df52b"
		score = 75
		quality = 85
		tags = "FILE"
		version = "1.0"

	strings:
		$a1 = ":\\System Volume Information\\{" wide
		$a2 = "\\\\.\\PhysicalDrive%d" wide
		$a3 = "DMWndClassX%d"
		$b1 = "{774476DF-C00F-4e3a-BF4A-6D8618CFA532}" ascii wide
		$b2 = "{820C02A4-578A-4750-A409-62C98F5E9237}" ascii wide

	condition:
		uint16(0)==0x5A4D and filesize <5000000 and ( all of ($a*) or any of ($b*))
}