rule SIGNATURE_BASE_Gen_Macro_Shellexecute_Action : FILE
{
	meta:
		description = "VBA macro technique to call ShellExecute to launch payload"
		author = "John Lambert @JohnLaTwC"
		id = "4ae3d3d9-de4a-5c5c-9a4a-bedc80b576be"
		date = "2019-01-08"
		modified = "2023-12-05"
		reference = "https://twitter.com/ItsReallyNick/status/1091170625698316288"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_macro_ShellExecute_action.yar#L1-L33"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "da40175579f7d76d10ad0188851f111ba5d875ce990b2940166dd28eac2a742d"
		score = 75
		quality = 85
		tags = "FILE"
		note = "This rule only works on VT or systems that perform macro subfile extraction"
		hash1 = "0878eec9ecae493659e42c1d87588573c1e6fc30acf7a59e6fdb5296b1c198ef"
		hash2 = "a0963ac15339c9803b4355fd71b68bf6ddedad960d5b3ad40bae873263470191"
		hash3 = "dd094e44a817604596d1ab06ca6e9597d49ca0a2cbe9239c73ceaad70265ec2a"
		hash4 = "7b9094ea41e89379c7048ef784ef494c4597ea0d31b707dcb9c8495f241f5fb0"
		hash5 = "35d8242726b905882bbfcf2770f84cb6f40552e76bff8fb0082ca10de3d61e54"
		hash6 = "bf9ff20d814bf21d46a22abbd7a8ad0276145807f9adf8d2787df9e3fce3f35d"
		hash7 = "77966004fcbff147f6923b3405ad9ad4e1dda42d0931564d0cdc4c7e1c91106a"
		hash8 = "c77c8033a1e5f694fa119dd7f78811f6015726822121b9414fc01e7de8770447"

	strings:
		$com1a = "00A0C91F3880"
		$com1b = "C08AFD90"
		$com2a = "00A0C90A8F39"
		$com2b = "9BA05972"
		$s3 = "ShellExecute" fullword
		$s4 = "GetObject" fullword

	condition:
		filesize <1MB and ( uint32be(0)==0x41747472 or uint32be(0)==0x61747472 or uint32be(0)==0x41545452) and all of ($s*) and ( all of ($com1*) or all of ($com2*))
}