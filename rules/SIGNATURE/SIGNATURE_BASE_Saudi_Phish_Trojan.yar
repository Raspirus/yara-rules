rule SIGNATURE_BASE_Saudi_Phish_Trojan : FILE
{
	meta:
		description = "Detects a trojan used in Saudi Aramco Phishing"
		author = "Florian Roth (Nextron Systems)"
		id = "d805391d-1256-5dac-8585-ccf3391d4e91"
		date = "2017-10-12"
		modified = "2023-12-05"
		reference = "https://goo.gl/Z3JUAA"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_saudi_aramco_phish.yar#L10-L27"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f7199d2e408cc057d88234e4041c7d87652d1ed361eaaf75bb37da45900e9f38"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "8ad94dc5d59aa1e9962c76fd5ca042e582566049a97aef9f5730ba779e5ebb91"

	strings:
		$s1 = { 7B 00 30 00 7D 00 7B 00 31 00 7D 00 5C 00 00 09
               2E 00 64 00 6C 00 6C 00 00 11 77 00 33 00 77 00
               70 00 2E 00 65 00 78 00 65 00 00 1B 61 00 73 00
               70 00 6E 00 65 00 74 00 5F 00 77 00 70 00 2E 00
               65 00 78 00 65 }

	condition:
		( uint16(0)==0x5a4d and filesize <3000KB and 1 of them )
}