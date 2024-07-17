import "pe"


rule SIGNATURE_BASE_TA17_318A_Rc4_Stack_Key_Fallchill : FILE
{
	meta:
		description = "HiddenCobra FallChill - rc4_stack_key"
		author = "US CERT"
		id = "0a2afcab-f540-592f-aa75-64c0a13d26f3"
		date = "2017-11-15"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-318B"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ta17_318A.yar#L10-L21"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f284cb492ff5242d7bf577580fd95723ef7d3f109c7217a26bbefbbff7150255"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$stack_key = { 0d 06 09 2a ?? ?? ?? ?? 86 48 86 f7 ?? ?? ?? ?? 0d 01 01 01 ?? ?? ?? ?? 05 00 03 82 41 8b c9 41 8b d1 49 8b 40 08 48 ff c2 88 4c 02 ff ff c1 81 f9 00 01 00 00 7c eb }

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and $stack_key
}