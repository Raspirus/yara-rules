rule SIGNATURE_BASE_Ophoneybee_Maocheng_Dropper : FILE
{
	meta:
		description = "Detects MaoCheng dropper from Operation Honeybee"
		author = "Florian Roth (Nextron Systems)"
		id = "b163e08e-3892-55f6-ae3e-30d2ba3f4310"
		date = "2018-03-03"
		modified = "2023-12-05"
		reference = "https://goo.gl/JAHZVL"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_op_honeybee.yar#L73-L86"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "85bcde1d821c052636a75dce4d8c3753188dd7da5fce2b3401d51c02d1c2fa6b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "35904f482d37f5ce6034d6042bae207418e450f4"

	strings:
		$x1 = "\\MaoCheng\\Release\\" ascii

	condition:
		uint16(0)==0x5a4d and filesize <600KB and 1 of them
}