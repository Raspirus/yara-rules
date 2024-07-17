rule SIGNATURE_BASE_Lokibot_Dropper_Packed_R11_Feb18 : FILE
{
	meta:
		description = "Auto-generated rule - file scan copy.pdf.r11"
		author = "Florian Roth (Nextron Systems)"
		id = "83cd6225-eb6d-5d17-a751-51f20db9c7eb"
		date = "2018-02-14"
		modified = "2023-12-05"
		reference = "https://app.any.run/tasks/401df4d9-098b-4fd0-86e0-7a52ce6ddbf5"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_loki_bot.yar#L33-L46"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "9ca39cac8dcbbbe1697ef96bde60c522bb9cc190c208483220aa96bc672f325a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "3b248d40fd7acb839cc592def1ed7652734e0e5ef93368be3c36c042883a3029"

	strings:
		$s1 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii

	condition:
		uint16(0)==0x0000 and filesize <2000KB and 1 of them
}