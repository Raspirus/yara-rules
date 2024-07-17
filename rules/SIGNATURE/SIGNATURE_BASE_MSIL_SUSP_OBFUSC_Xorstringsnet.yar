
rule SIGNATURE_BASE_MSIL_SUSP_OBFUSC_Xorstringsnet : FILE
{
	meta:
		description = "Detects XorStringsNET string encryption, and other obfuscators derived from it"
		author = "dr4k0nia"
		id = "f0724ca6-4bfe-5b88-9396-a58aa7461fd6"
		date = "2023-03-26"
		modified = "2023-12-05"
		reference = "https://github.com/dr4k0nia/yara-rules"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_net_xorstrings.yar#L2-L27"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "6d023a80bd8f5709721c3ace8a7230b847ca4bd2a1aff502a25333ffc8bf75ca"
		score = 75
		quality = 85
		tags = "FILE"
		version = "1.0"

	strings:
		$pattern = { 06 1E 58 07 8E 69 FE 17 }
		$a1 = "_CorDllMain" ascii
		$a2 = "_CorExeMain" ascii
		$a3 = "mscorlib" ascii fullword
		$a4 = ".cctor" ascii fullword
		$a5 = "System.Private.Corlib" ascii
		$a6 = "<Module>" ascii fullword
		$a7 = "<PrivateImplementationsDetails{" ascii

	condition:
		uint16(0)==0x5a4d and filesize <25MB and $pattern and 2 of ($a*)
}