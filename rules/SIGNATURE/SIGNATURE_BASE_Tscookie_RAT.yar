rule SIGNATURE_BASE_Tscookie_RAT : FILE
{
	meta:
		description = "Detects TSCookie RAT"
		author = "Florian Roth (Nextron Systems)"
		id = "a2b6c598-4498-5c0a-9257-b0bf6cd28de9"
		date = "2018-03-06"
		modified = "2023-12-05"
		reference = "http://blog.jpcert.or.jp/2018/03/malware-tscooki-7aa0.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_tscookie_rat.yar#L13-L32"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c6121c541a77219b17351787973a4bc06a8d941ebd5f9e5e1e14ad4740a3fe7b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2bd13d63797864a70b775bd1994016f5052dc8fd1fd83ce1c13234b5d304330d"

	strings:
		$x1 = "[-] DecryptPassword_Outlook failed(err=%d)" fullword ascii
		$x2 = "----------------------- Firefox Passwords ------------------" fullword ascii
		$x3 = "--------------- Outlook Passwords ------------------" fullword ascii
		$x4 = "----------------------- IE Passwords ------------------" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and ((pe.exports("DoWork") and pe.exports("PrintF")) or 1 of them )
}