rule SIGNATURE_BASE_APT_Webshell_AUS_Tiny_2 : FILE
{
	meta:
		description = "Detetcs a tiny webshell involved in the Australian Parliament House network compromise"
		author = "Florian Roth (Nextron Systems)"
		id = "4746d4ce-628a-59b0-9032-7e0759d96ad3"
		date = "2019-02-18"
		modified = "2023-12-05"
		reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_aus_parl_compromise.yar#L25-L38"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e26c265d2b1606257d8c843921601f14cae2beaf246f8e37daeeb6c5ff12f289"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "0d6209d86f77a0a69451b0f27b476580c14e0cda15fa6a5003aab57a93e7e5a5"

	strings:
		$x1 = "Request.Item[System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(\"[password]\"))];" ascii
		$x2 = "eval(arguments,System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(\"" ascii

	condition:
		( uint16(0)==0x3f3c or uint16(0)==0x253c) and filesize <1KB and 1 of them
}