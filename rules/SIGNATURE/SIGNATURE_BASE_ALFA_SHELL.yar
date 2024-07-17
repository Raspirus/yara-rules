rule SIGNATURE_BASE_ALFA_SHELL : FILE
{
	meta:
		description = "Detects web shell often used by Iranian APT groups"
		author = "Florian Roth (Nextron Systems)"
		id = "f0be44ec-bff0-5d01-aabd-df7aa05383e3"
		date = "2017-09-21"
		modified = "2023-12-05"
		reference = "Internal Research - APT33"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-webshells.yar#L9814-L9832"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "651568b2b95c9e5c2b60fb3245e5afe4290235979e3df15bad96ccd08ae234ef"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a39d8823d54c55e60a7395772e50d116408804c1a5368391a1e5871dbdc83547"

	strings:
		$x1 = "$OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64')" ascii
		$x2 = "#solevisible@gmail.com" fullword ascii
		$x3 = "'login_page' => '500',//gui or 500 or 403 or 404" fullword ascii
		$x4 = "$GLOBALS['__ALFA__']" fullword ascii
		$x5 = "if(!function_exists('b'.'as'.'e6'.'4_'.'en'.'co'.'de')" ascii
		$f1 = { 76 2F 38 76 2F 36 76 2F 2B 76 2F 2F 66 38 46 27 29 3B 3F 3E 0D 0A }

	condition:
		( filesize <900KB and 2 of ($x*) or $f1 at ( filesize -22))
}