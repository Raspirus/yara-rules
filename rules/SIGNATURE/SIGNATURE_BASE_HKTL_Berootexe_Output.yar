import "pe"


rule SIGNATURE_BASE_HKTL_Berootexe_Output : FILE
{
	meta:
		description = "Detects the output of beRoot.exe"
		author = "Tobias Michalski"
		id = "dfd11915-443f-5ce9-b94a-bdcb0e62104e"
		date = "2018-07-25"
		modified = "2023-12-05"
		reference = "https://github.com/AlessandroZ/BeRoot/tree/master/Windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L4449-L4463"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7886535d071092df76507f0dd431409e85c368d404f49e7f118278f6565618e6"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "permissions: {'change_config'" fullword wide
		$s2 = "Full path: C:\\Windows\\system32\\msiexec.exe /V" fullword wide
		$s3 = "Full path: C:\\Windows\\system32\\svchost.exe -k DevicesFlow" fullword wide
		$s4 = "! BANG BANG !" fullword wide

	condition:
		filesize <400KB and 3 of them
}