
rule SIGNATURE_BASE_APT_Hiddencobra_Import_Obfuscation_2 : HIDDEN_COBRA TYPEFRAME FILE
{
	meta:
		description = "Hidden Cobra - Detects remote access trojan"
		author = "NCCIC trusted 3rd party - Edit: Tobias Michalski"
		id = "bc139580-a55b-514f-8a4e-ca1402ce3ad9"
		date = "2018-04-12"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/analysis-reports/AR18-165A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ar18_165a.yar#L21-L41"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d52fc053afc6b3beb35a6dfd0f9b3714a5bad4e9b0dcfcce7be87d65f0a0c23e"
		score = 75
		quality = 85
		tags = "HIDDEN_COBRA, TYPEFRAME, FILE"
		incident = "10135536"
		category = "hidden_cobra"
		family = "TYPEFRAME"
		hash0 = "bfb41bc0c3856aa0a81a5256b7b8da51"

	strings:
		$s0 = {A6 D6 02 EB 4E B2 41 EB C3 EF 1F}
		$s1 = {B6 DF 01 FD 48 B5 }
		$s2 = {B6 D5 0E F3 4E B5 }
		$s3 = {B7 DF 0E EE }
		$s4 = {B6 DF 03 FC }
		$s5 = {A7 D3 03 FC }

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and all of them
}