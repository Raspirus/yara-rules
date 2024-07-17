rule SIGNATURE_BASE_Gen_Python_Encoded_Adware : FILE
{
	meta:
		description = "Encoded Python payload for adware"
		author = "John Lambert @JohnLaTwC"
		id = "7b4b422b-c960-5ab3-a6a7-a30e416efdec"
		date = "2018-03-07"
		modified = "2023-01-06"
		reference = "https://twitter.com/JohnLaTwC/status/949048002466914304"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_python_encoded_adware.yar#L1-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "5d7239be779367e69d2e63ffd9dc6e2a1f79c4e5c6c725e8c5e59a44c0ab2fff"
		logic_hash = "256b289cfe83384c02aacf9c7e790898ba34988c9be149b39e63791c319bfc4a"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$r1 = "=__import__(\"base64\").b64decode"
		$s1 = "bytes(map(lambda"
		$s2 = "[1]^"

	condition:
		filesize <100KB and @r1<100 and all of them
}