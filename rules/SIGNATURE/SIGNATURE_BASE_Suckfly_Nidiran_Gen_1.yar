rule SIGNATURE_BASE_Suckfly_Nidiran_Gen_1 : FILE
{
	meta:
		description = "Detects Suckfly Nidiran Trojan"
		author = "Florian Roth (Nextron Systems)"
		id = "1abc596a-5fb1-55f9-b72d-022bfc6d10c7"
		date = "2018-01-28"
		modified = "2023-12-05"
		reference = "https://www.symantec.com/connect/blogs/suckfly-revealing-secret-life-your-code-signing-certificates"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_suckfly.yar#L14-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "bf617259df00b16272caffa8f1ffcf8d29cb98cb6ab85ca52e0bb0706f0cd5b0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "ac7d7c676f58ebfa5def9b84553f00f283c61e4a310459178ea9e7164004e734"

	strings:
		$s1 = "WriteProcessMemory fail at %d " fullword ascii
		$s2 = "CreateRemoteThread fail at %d " fullword ascii
		$s3 = "CreateRemoteThread Succ" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and 2 of them
}