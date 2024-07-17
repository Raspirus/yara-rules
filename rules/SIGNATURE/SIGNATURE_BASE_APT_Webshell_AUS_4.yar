
rule SIGNATURE_BASE_APT_Webshell_AUS_4 : FILE
{
	meta:
		description = "Detetcs a webshell involved in the Australian Parliament House network compromise"
		author = "Florian Roth (Nextron Systems)"
		id = "bb5b10d1-3528-5361-92fc-8440c65dcda4"
		date = "2019-02-18"
		modified = "2023-12-05"
		reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_aus_parl_compromise.yar#L56-L71"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4a4f26b50631021979e4a8246a1e1c10150f4fb03eb7d77a1042e41ef57b3961"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "83321c02339bb51735fbcd9a80c056bd3b89655f3dc41e5fef07ca46af09bb71"

	strings:
		$s1 = "wProxy.Credentials = new System.Net.NetworkCredential(pusr, ppwd);" fullword ascii
		$s2 = "{return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(" ascii
		$s3 = ".Equals('User-Agent', StringComparison.OrdinalIgnoreCase))" ascii
		$s4 = "gen.Emit(System.Reflection.Emit.OpCodes.Ret);" fullword ascii

	condition:
		uint16(0)==0x7566 and filesize <10KB and 3 of them
}