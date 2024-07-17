
rule SIGNATURE_BASE_APT_Area1_SSF_Googlesend_Strings : FILE
{
	meta:
		description = "Detects send tool used in phishing campaign reported by Area 1 in December 2018"
		author = "Area 1 (modified by Florian Roth)"
		id = "66a2faa1-b133-528c-91a9-06a43d2c00a0"
		date = "2018-12-19"
		modified = "2023-12-05"
		reference = "https://cdn.area1security.com/reports/Area-1-Security-PhishingDiplomacy.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_area1_phishing_diplomacy.yar#L29-L46"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3a373ed63494b67883515c133bf5b0af3ab874397c7cb45c8399f12e35212be4"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$conf = "RefreshToken.ini" wide
		$client_id = "Enter your client ID here" wide
		$client_secret = "Enter your client secret here" wide
		$status = "We are going to send" wide
		$s1 = { b8 00 01 00 00 f0 0f b0 23 74 94 f3 90 80 3d ?? ?? ?? ?? 00 75 ??
         51 52 6a 00 e8 ?? ?? ?? ?? 5a 59 b8 00 01 00 00 f0 0f b0
         23 0f ?? ?? ?? ?? ?? 51 52 6a 0a e8 ?? ?? ?? ?? 5a 59 eb c3 }

	condition:
		uint16(0)==0x5a4d and 3 of them
}