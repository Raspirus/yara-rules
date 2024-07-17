rule SIGNATURE_BASE_APT_FIN7_Maldoc_Aug18_1 : FILE
{
	meta:
		description = "Detects malicious Doc from FIN7 campaign"
		author = "Florian Roth (Nextron Systems)"
		id = "f3c430e0-be9a-5c3f-9378-a20ef0492afb"
		date = "2018-08-01"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_fin7.yar#L51-L64"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f3ecf77a5f909361f4a6af5ca0f25ec85721570587500a8ce2ef203158472e47"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "9c12591c850a2d5355be0ed9b3891ccb3f42e37eaf979ae545f2f008b5d124d6"

	strings:
		$s1 = "<photoshop:LayerText>If this document was downloaded from your email, please click  \"Enable editing\" from the yellow bar above" ascii

	condition:
		filesize <800KB and 1 of them
}