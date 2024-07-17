
rule SIGNATURE_BASE_APT_HKTL_Wiper_Whispergate_Jan22_2 : FILE
{
	meta:
		description = "Detects unknown wiper malware"
		author = "Florian Roth (Nextron Systems)"
		id = "822e5af5-9c51-5be3-94f1-7e0a714743e6"
		date = "2022-01-16"
		modified = "2023-12-05"
		reference = "https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ua_wiper_whispergate.yar#L25-L57"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "87a03e95bc1c33d1b3343ec7369c516bb15791943fbb122de11867ad4bddd565"
		score = 90
		quality = 85
		tags = "FILE"
		hash1 = "dcbbae5a1c61dbbbb7dcd6dc5dd1eb1169f5329958d38b58c3fd9384081c9b78"

	strings:
		$sc1 = { 70 00 6F 00 77 00 65 00 72 00 73 00 68 00 65 00
               6C 00 6C 00 00 27 2D 00 65 00 6E 00 63 00 20 00
               55 00 77 00 42 00 30 00 41 00 47 00 45 00 41 00
               63 00 67 00 42 00 30 00 41 00 43 }
		$sc2 = { 59 00 6C 00 66 00 77 00 64 00 77 00 67 00 6D 00
               70 00 69 00 6C 00 7A 00 79 00 61 00 70 00 68 }
		$s1 = "xownxloxadDxatxxax" wide
		$s2 = "0AUwBsAGUAZQBwACAALQBzACAAMQAwAA==" wide
		$s3 = "https://cdn.discordapp.com/attachments/" wide
		$s4 = "fffxfff.fff" ascii fullword
		$op1 = { 20 6b 85 b9 03 20 14 19 91 52 61 65 20 e1 ae f1 }
		$op2 = { aa ae 74 20 d9 7c 71 04 59 20 71 cc 13 91 61 20 97 3c 2a c0 }
		$op3 = { 38 9c f3 ff ff 20 f2 96 4d e9 20 5d ae d9 ce 58 20 4f 45 27 }
		$op4 = { d4 67 d4 61 80 1c 00 00 04 38 35 02 00 00 20 27 c0 db 56 65 20 3d eb 24 de 61 }

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and 5 of them or 7 of them
}