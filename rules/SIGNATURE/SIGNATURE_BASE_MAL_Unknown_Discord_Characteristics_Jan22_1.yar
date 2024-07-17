
rule SIGNATURE_BASE_MAL_Unknown_Discord_Characteristics_Jan22_1 : FILE
{
	meta:
		description = "Detects unknown malware with a few indicators also found in Wiper malware"
		author = "Florian Roth (Nextron Systems)"
		id = "23ee5319-6a72-517b-8ea0-55063b6b862c"
		date = "2022-01-16"
		modified = "2023-12-05"
		reference = "https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ua_wiper_whispergate.yar#L103-L119"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f9cf4a15be0ab35a0d0f0c9b1a191f623f905c8fc9da651872de7c025a27a806"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "dcbbae5a1c61dbbbb7dcd6dc5dd1eb1169f5329958d38b58c3fd9384081c9b78"

	strings:
		$x1 = "xownxloxadDxatxxax" wide
		$s2 = "https://cdn.discordapp.com/attachments/" wide

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and all of them
}