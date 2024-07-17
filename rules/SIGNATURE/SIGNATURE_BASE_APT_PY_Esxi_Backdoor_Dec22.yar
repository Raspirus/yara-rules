rule SIGNATURE_BASE_APT_PY_Esxi_Backdoor_Dec22 : FILE
{
	meta:
		description = "Detects Python backdoor found on ESXi servers"
		author = "Florian Roth"
		id = "f0a3b9b9-0031-5d9f-97f8-70f83863ee63"
		date = "2022-12-14"
		modified = "2023-12-05"
		reference = "https://blogs.juniper.net/en-us/threat-research/a-custom-python-backdoor-for-vmware-esxi-servers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/mal_ransom_esxi_attacks_feb23.yar#L58-L71"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "86b628f007720aa706c30d91e845d867ed481d1e99bcc9315c84a4e0b7b1b2a6"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "cmd = str(base64.b64decode(encoded_cmd), " ascii
		$x2 = "sh -i 2>&1 | nc %s %s > /tmp/" ascii

	condition:
		filesize <10KB and 1 of them or all of them
}