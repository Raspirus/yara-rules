rule SIGNATURE_BASE_SUSP_Reversed_Base64_Encoded_EXE : FILE
{
	meta:
		description = "Detects an base64 encoded executable with reversed characters"
		author = "Florian Roth (Nextron Systems)"
		id = "3b52e59e-7c0a-560f-8123-1099c52e7e3d"
		date = "2020-04-06"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_susp_obfuscation.yar#L47-L68"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0a2f1caf2235ee24f531c9f9a5ebdc0c97a90890218669749a4c83bede80a336"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "7e6d9a5d3b26fd1af7d58be68f524c4c55285b78304a65ec43073b139c9407a8"

	strings:
		$s1 = "AEAAAAEQATpVT"
		$s2 = "AAAAAAAAAAoVT"
		$s3 = "AEAAAAEAAAqVT"
		$s4 = "AEAAAAIAAQpVT"
		$s5 = "AEAAAAMAAQqVT"
		$sh1 = "SZk9WbgM1TEBibpBib1JHIlJGI09mbuF2Yg0WYyd2byBHIzlGaU" ascii
		$sh2 = "LlR2btByUPREIulGIuVncgUmYgQ3bu5WYjBSbhJ3ZvJHcgMXaoR" ascii
		$sh3 = "uUGZv1GIT9ERg4Wag4WdyBSZiBCdv5mbhNGItFmcn9mcwBycphGV" ascii

	condition:
		filesize <10000KB and 1 of them
}