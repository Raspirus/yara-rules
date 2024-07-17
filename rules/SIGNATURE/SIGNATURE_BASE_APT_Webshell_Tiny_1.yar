rule SIGNATURE_BASE_APT_Webshell_Tiny_1 : FILE
{
	meta:
		description = "Detetcs a tiny webshell involved in the Australian Parliament House network compromise"
		author = "Florian Roth (Nextron Systems)"
		id = "e65a8920-0684-5aae-a2b8-079c2beae08a"
		date = "2019-02-18"
		modified = "2023-12-05"
		reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_aus_parl_compromise.yar#L12-L23"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "277162f720195c94d36fd3350d0dda785007e8cc6ed2ab2aa1a6a6262f2993fa"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "eval(" ascii wide

	condition:
		( uint16(0)==0x3f3c or uint16(0)==0x253c) and filesize <40 and $x1
}