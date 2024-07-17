rule SIGNATURE_BASE_WEBSHELL_Z_Webshell_2 : FILE
{
	meta:
		description = "Detection for the z_webshell"
		author = "DHS NCCIC Hunt and Incident Response Team"
		id = "9a54925f-de10-567f-a1ea-5e7522b47dfd"
		date = "2018-01-25"
		modified = "2023-12-05"
		old_rule_name = "z_webshell"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ta18_074A.yar#L9-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "2c9095c965a55efc46e16b86f9b7d6c6"
		logic_hash = "d41aa107e54af5d45531a46d24b24f9f14635dbcb50ed26f7c787883854f961f"
		score = 75
		quality = 81
		tags = "FILE"

	strings:
		$webshell_name = "public string z_progname =" nocase ascii wide
		$webshell_password = "public string Password =" nocase ascii wide

	condition:
		( uint32(0)==0x2040253c or uint32(0)==0x7073613c) and filesize <100KB and 2 of ($webshell_*)
}