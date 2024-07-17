
rule SIGNATURE_BASE_SUSP_EXPL_LIBCUE_CVE_2023_43641_Oct23_1 : CVE_2023_43641 FILE
{
	meta:
		description = "Detects a suspicious .cue file that could be an exploitation attempt of libcue vulnerability CVE-2023-43641"
		author = "Florian Roth"
		id = "34fcf80c-adcd-55c0-9fb4-261d20f61fa6"
		date = "2023-10-27"
		modified = "2023-12-05"
		reference = "https://github.com/github/securitylab/blob/main/SecurityExploits/libcue/track_set_index_CVE-2023-43641/README.md"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_libcue_cve_2023_43641.yar#L2-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a2cd3c1b0b3551ffb24bf7704c37c1be6c1a9655c74447d2f7f94540dd0ab188"
		score = 70
		quality = 85
		tags = "CVE-2023-43641, FILE"

	strings:
		$a1 = "TRACK "
		$a2 = "FILE "
		$s1 = "INDEX 4294"

	condition:
		filesize <100KB and all of them
}