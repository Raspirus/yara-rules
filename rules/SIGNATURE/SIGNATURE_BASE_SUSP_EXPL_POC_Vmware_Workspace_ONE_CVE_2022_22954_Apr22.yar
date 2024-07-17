
rule SIGNATURE_BASE_SUSP_EXPL_POC_Vmware_Workspace_ONE_CVE_2022_22954_Apr22 : CVE_2022_22954
{
	meta:
		description = "Detects payload as seen in PoC code to exploit Workspace ONE Access freemarker server-side template injection CVE-2022-22954"
		author = "Florian Roth"
		id = "b7b7cefb-96f5-53f9-b6fc-6e798f557c5d"
		date = "2022-04-08"
		modified = "2023-04-28"
		old_rule_name = "EXPL_POC_VMWare_Workspace_ONE_CVE_2022_22954_Apr22"
		reference = "https://twitter.com/rwincey/status/1512241638994853891/photo/1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/exploit_cve_2022_22954_vmware_workspace_one.yar#L2-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "2fb23bfc28140f818b9fc630b0c1bf0c70a8f4f85b9516cefe2ff26a9de6516c"
		score = 70
		quality = 85
		tags = "CVE-2022-22954"

	strings:
		$x1 = "66%72%65%65%6d%61%72%6b%65%72%2e%74%65%6d%70%6c%61%74%65%2e%75%74%69%6c%69%74%79%2e%45%78%65%63%75%74%65%22%3f%6e%65%77%28%29%28" ascii
		$x2 = "${\"freemarker.template.utility.Execute\"?new()("
		$x3 = "cat /etc/passwd\")).(#execute=#instancemanager.newInstance(\"freemarker.template.utility.Execute"
		$x4 = "cat /etc/passwd\\\")).(#execute=#instancemanager.newInstance(\\\"freemarker.template.utility.Execute"
		$x5 = "cat /etc/shadow\")).(#execute=#instancemanager.newInstance(\"freemarker.template.utility.Execute"
		$x6 = "cat /etc/shadow\\\")).(#execute=#instancemanager.newInstance(\\\"freemarker.template.utility.Execute"

	condition:
		1 of them
}