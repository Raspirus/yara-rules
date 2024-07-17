import "pe"


rule SIGNATURE_BASE_Turlamosquito_Mal_5 : FILE
{
	meta:
		description = "Detects malware sample from Turla Mosquito report"
		author = "Florian Roth (Nextron Systems)"
		id = "9f3a35c9-b0f0-5ca6-8b34-19e2d45305f2"
		date = "2018-02-22"
		modified = "2023-12-05"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_turla_mosquito.yar#L92-L103"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5b0366194410f36c47dd41f6a36c45edbce75e3ddad19520b17bed59513e1dbc"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "26a1a42bc74e14887616f9d6048c17b1b4231466716a6426e7162426e1a08030"

	condition:
		uint16(0)==0x5a4d and filesize <300KB and pe.imphash()=="ac40cf7479f53a4754ac6481a4f24e57"
}