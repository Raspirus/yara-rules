import "pe"


rule SIGNATURE_BASE_MAL_Trickbot_Oct19_6 : FILE
{
	meta:
		description = "Detects Trickbot malware"
		author = "Florian Roth (Nextron Systems)"
		id = "5feb8d34-4974-5315-a5f9-79a3fac83d1d"
		date = "2019-10-02"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_trickbot.yar#L98-L115"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "599b1f56483f4ea267595b90dd4ef93b7e2147e4a0d8449cdd9d2539a96c3f79"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "cf99990bee6c378cbf56239b3cc88276eec348d82740f84e9d5c343751f82560"
		hash2 = "cf99990bee6c378cbf56239b3cc88276eec348d82740f84e9d5c343751f82560"

	strings:
		$x1 = "D:\\MyProjects\\spreader\\Release\\ssExecutor_x86.pdb" fullword ascii
		$s1 = "%s\\appdata\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\%s" fullword ascii
		$s2 = "%s\\appdata\\roaming\\%s" fullword ascii
		$s3 = "WINDOWS\\SYSTEM32\\TASKS" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <=400KB and (1 of ($x*) or 3 of them )
}