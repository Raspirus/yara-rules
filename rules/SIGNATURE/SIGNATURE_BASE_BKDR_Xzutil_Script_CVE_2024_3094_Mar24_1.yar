rule SIGNATURE_BASE_BKDR_Xzutil_Script_CVE_2024_3094_Mar24_1 : CVE_2024_3094
{
	meta:
		description = "Detects make file and script contents used by the backdoored XZ library (xzutil) CVE-2024-3094."
		author = "Florian Roth"
		id = "6b62ffc2-d0a7-5810-97a3-c48f7fac300e"
		date = "2024-03-30"
		modified = "2024-04-24"
		reference = "https://www.openwall.com/lists/oss-security/2024/03/29/4"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/bkdr_xz_util_cve_2024_3094.yar#L2-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "d44d0425769fa2e0b6875e5ca25d45b251bbe98870c6b9bef34f7cea9f84c9c3"
		logic_hash = "8d3f5f078a5c827208e04acb7ac1496f473e1236f92561f94d2a3c8156c68ea6"
		score = 80
		quality = 85
		tags = "CVE-2024-3094"

	strings:
		$x1 = "/bad-3-corrupt_lzma2.xz | tr " ascii
		$x2 = "/tests/files/good-large_compressed.lzma|eval $i|tail -c +31265|" ascii
		$x3 = "eval $zrKcKQ" ascii

	condition:
		1 of them
}