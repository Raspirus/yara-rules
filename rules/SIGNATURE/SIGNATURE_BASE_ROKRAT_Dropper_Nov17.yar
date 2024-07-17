rule SIGNATURE_BASE_ROKRAT_Dropper_Nov17 : FILE
{
	meta:
		description = "Detects dropper for ROKRAT malware"
		author = "Florian Roth (Nextron Systems)"
		id = "4f3156a2-6b1b-5c65-b8fa-84c0b739d703"
		date = "2017-11-28"
		modified = "2023-12-05"
		reference = "http://blog.talosintelligence.com/2017/11/ROKRAT-Reloaded.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_rokrat.yar#L48-L61"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4a444342a4fb4d10aaf8efb5c26954847ce1089c9cec37d1ab3b03e0ac566c6c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "eb6d25e08b2b32a736b57f8df22db6d03dc82f16da554f4e8bb67120eacb1d14"
		hash2 = "a29b07a6fe5d7ce3147dd7ef1d7d18df16e347f37282c43139d53cce25ae7037"

	condition:
		uint16(0)==0x5a4d and filesize <2500KB and pe.imphash()=="c6187b1b5f4433318748457719dd6f39"
}