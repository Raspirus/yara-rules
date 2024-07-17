rule SIGNATURE_BASE_APT_MAL_LNX_Hunting_Linux_WHIRLPOOL_1 : FILE
{
	meta:
		description = "Hunting rule looking for strings observed in WHIRLPOOL samples."
		author = "Mandiant"
		id = "a997bd65-c502-53a0-8bb8-62daaa916f0d"
		date = "2023-06-15"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_barracuda_esg_unc4841_jun23.yar#L154-L173"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "177add288b289d43236d2dba33e65956"
		logic_hash = "d03c0e292b9b97bbf76585fc74208e4263d753807b8e4a445be80d41264d5432"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "error -1 exit" fullword
		$s2 = "create socket error: %s(error: %d)\n" fullword
		$s3 = "connect error: %s(error: %d)\n" fullword
		$s4 = {C7 00 20 32 3E 26 66 C7 40 04 31 00}
		$c1 = "plain_connect" fullword
		$c2 = "ssl_connect" fullword
		$c3 = "SSLShell.c" fullword

	condition:
		uint32(0)==0x464c457f and filesize <15MB and ( all of ($s*) or all of ($c*))
}