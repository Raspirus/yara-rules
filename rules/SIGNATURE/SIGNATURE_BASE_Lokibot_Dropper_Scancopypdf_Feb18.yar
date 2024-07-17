
rule SIGNATURE_BASE_Lokibot_Dropper_Scancopypdf_Feb18 : FILE
{
	meta:
		description = "Auto-generated rule - file Scan Copy.pdf.com"
		author = "Florian Roth (Nextron Systems)"
		id = "64c45d91-4e18-5fd1-8d93-b5db4df7da29"
		date = "2018-02-14"
		modified = "2023-12-05"
		reference = "https://app.any.run/tasks/401df4d9-098b-4fd0-86e0-7a52ce6ddbf5"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_loki_bot.yar#L11-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b9f10a09d91c10731e34dc88f87104693cdc794ddc3c63ee382f976d0a75f30f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "6f8ff26a5daf47effdea5795cdadfff9265c93a0ebca0ce5a4144712f8cab5be"

	strings:
		$x1 = "Win32           Scan Copy.pdf   " fullword wide
		$a1 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
		$s1 = "Compiling2.exe" fullword wide
		$s2 = "Unstalled2" fullword ascii
		$s3 = "Compiling.exe" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and $x1 or ($a1 and 1 of ($s*))
}