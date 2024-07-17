rule SIGNATURE_BASE_SUSP_Themebleed_Theme_Sep23 : FILE
{
	meta:
		description = "Detects domain or IP placement in Windows theme files"
		author = "@m_haggis, @nas_bench"
		id = "76d0042b-655d-5d03-bcc4-150ebc92eb43"
		date = "2023-09-13"
		modified = "2023-12-05"
		reference = "https://github.com/gabe-k/themebleed"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/exploit_cve_2023_38146.yar#L1-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "577003741f07aeffafd2b0b22913de44ea4f5ed264f4104ee013104355f65311"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = /Path=\\\\[0-9a-zA-Z\.-]{1,20}\\/
		$s2 = "[VisualStyles]"
		$s3 = "[Theme]"

	condition:
		filesize <1MB and all of them
}