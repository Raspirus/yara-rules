
rule SIGNATURE_BASE_EXPL_Gitlab_CE_RCE_CVE_2021_22205 : CVE_2021_22205
{
	meta:
		description = "Detects signs of exploitation of GitLab CE CVE-2021-22205"
		author = "Florian Roth (Nextron Systems)"
		id = "21cc6fa7-e50d-5b8e-815d-27315ab5635d"
		date = "2021-10-26"
		modified = "2023-12-05"
		reference = "https://security.humanativaspa.it/gitlab-ce-cve-2021-22205-in-the-wild/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/exploit_gitlab_cve_2021_22205.yar#L2-L27"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "54b841716a6bd56706c1c38fcda9a27ffd7feba2660602b191e8e347983e578d"
		score = 70
		quality = 85
		tags = "CVE-2021-22205"

	strings:
		$sa1 = "VXNlci5maW5kX2J5KHVzZXJuYW1l" ascii
		$sa2 = "VzZXIuZmluZF9ieSh1c2VybmFtZ" ascii
		$sa3 = "Vc2VyLmZpbmRfYnkodXNlcm5hbW" ascii
		$sb1 = "dXNlci5hZG1pb" ascii
		$sb2 = "VzZXIuYWRtaW" ascii
		$sb3 = "1c2VyLmFkbWlu" ascii
		$sc1 = "dXNlci5zYXZlI" ascii
		$sc2 = "VzZXIuc2F2ZS" ascii
		$sc3 = "1c2VyLnNhdmUh" ascii

	condition:
		1 of ($sa*) and 1 of ($sb*) and 1 of ($sc*)
}