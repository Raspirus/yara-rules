
rule SIGNATURE_BASE_VULN_Python_Hack_Backdoored_Ctx_May21 : FILE
{
	meta:
		description = "Detects backdoored python ctx version"
		author = "Christian Burkard"
		id = "55c1326a-6a5f-5d6f-b798-2c8516faffe2"
		date = "2022-05-24"
		modified = "2023-12-05"
		reference = "https://twitter.com/s0md3v/status/1529005758540808192"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/vul_backdoor_antitheftweb.yar#L16-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f8047eb4e0420e4ec01fb038acdc4abdcc3aa4dada5ce072d20f78acac942079"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "4fdfd4e647c106cef2a3b2503473f9b68259cae45f89e5b6c9272d04a1dfaeb0"
		hash2 = "b40297af54e3f99b02e105f013265fd8d0a1b1e1f7f0b05bcb5dbdc9125b3bb5"
		hash3 = "b7644fa1e0872780690ce050c98aa2407c093473031ab5f7a8ce35c0d2fc077e"

	strings:
		$x1 = "requests.get(\"https://anti-theft-web.herokuapp.com/hacked/"

	condition:
		filesize <10KB and $x1
}