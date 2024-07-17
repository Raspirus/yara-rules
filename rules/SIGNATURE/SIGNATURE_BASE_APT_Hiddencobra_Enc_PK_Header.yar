rule SIGNATURE_BASE_APT_Hiddencobra_Enc_PK_Header : HIDDEN_COBRA TYPEFRAME FILE
{
	meta:
		description = "Hidden Cobra - Detects trojan with encrypted header"
		author = "NCCIC trusted 3rd party - Edit: Tobias Michalski"
		id = "5d7001b3-162c-5a97-a740-1b8e33d4aa9e"
		date = "2018-04-12"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/analysis-reports/AR18-165A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ar18_165a.yar#L2-L19"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d0c8345b69e5f421fd93bc239031f2e51a120ae64be1eca0c1fdae2aa55ac42a"
		score = 75
		quality = 85
		tags = "HIDDEN_COBRA, TYPEFRAME, FILE"
		incident = "10135536"
		category = "hidden_cobra"
		family = "TYPEFRAME"
		hash0 = "3229a6cea658b1b3ca5ca9ad7b40d8d4"

	strings:
		$s0 = { 5f a8 80 c5 a0 87 c7 f0 9e e6 }
		$s1 = { 95 f1 6e 9c 3f c1 2c 88 a0 5a }
		$s2 = { ae 1d af 74 c0 f5 e1 02 50 10 }

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and any of them
}