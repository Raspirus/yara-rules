
rule SIGNATURE_BASE_APT_Webshell_AUS_5 : FILE
{
	meta:
		description = "Detetcs a webshell involved in the Australian Parliament House network compromise"
		author = "Florian Roth (Nextron Systems)"
		id = "59b3f6aa-2d3b-54b4-b543-57bd9d981e87"
		date = "2019-02-18"
		modified = "2023-12-05"
		reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_aus_parl_compromise.yar#L92-L111"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "fb0e53e5561f7f14f2ad6afcda2798d353cf4d54d12ae3354b03d62ed0c00bf3"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "54a17fb257db2d09d61af510753fd5aa00537638a81d0a8762a5645b4ef977e4"

	strings:
		$a1 = "function DEC(d){return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(d));}" fullword ascii
		$a2 = "function ENC(d){return Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(d));}" fullword ascii
		$s1 = "var hash=DEC(Request.Item['" ascii
		$s2 = "Response.Write(ENC(SET_ASS_SUCCESS));" fullword ascii
		$s3 = "hashtable[hash] = assCode;" fullword ascii
		$s4 = "Response.Write(ss);" fullword ascii
		$s5 = "var hashtable = Application[CachePtr];" fullword ascii

	condition:
		uint16(0)==0x7566 and filesize <2KB and 4 of them
}