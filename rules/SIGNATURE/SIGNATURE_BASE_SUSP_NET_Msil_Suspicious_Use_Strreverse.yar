
rule SIGNATURE_BASE_SUSP_NET_Msil_Suspicious_Use_Strreverse : FILE
{
	meta:
		description = "Detects mixed use of Microsoft.CSharp and VisualBasic to use StrReverse"
		author = "dr4k0nia, modified by Florian Roth"
		id = "830dec40-4412-59c1-8b4d-a237f14acd30"
		date = "2023-01-31"
		modified = "2023-02-22"
		reference = "https://github.com/dr4k0nia/yara-rules"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_susp_net_msil.yar#L2-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "02ce0980427dea835fc9d9eed025dd26672bf2c15f0b10486ff8107ce3950701"
		logic_hash = "a7440600ee4826568d465d204e0a602f61752e4ffcfa3b4f29e5bc81c4d67b46"
		score = 70
		quality = 85
		tags = "FILE"
		version = "1.1"

	strings:
		$a1 = ", PublicKeyToken="
		$a2 = ".NETFramework,Version="
		$csharp = "Microsoft.CSharp"
		$vbnet = "Microsoft.VisualBasic"
		$strreverse = "StrReverse"

	condition:
		uint16(0)==0x5a4d and filesize <50MB and all of ($a*) and $csharp and $vbnet and $strreverse
}