
rule SIGNATURE_BASE_APT_MAL_ASPX_HAFNIUM_Chopper_Mar21_4 : FILE
{
	meta:
		description = "Detects HAFNIUM ASPX files dropped on compromised servers"
		author = "Florian Roth (Nextron Systems)"
		id = "93f5b682-642d-5edf-84a9-296bf12cd72b"
		date = "2021-03-07"
		modified = "2023-12-05"
		reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_hafnium.yar#L218-L233"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "933ab74a0e30e2a728444d491c9eb0ff134db05d905aeb48efe3ba65674a3730"
		score = 85
		quality = 79
		tags = "FILE"

	strings:
		$s1 = "<%@Page Language=\"Jscript\"%>" ascii wide nocase
		$s2 = ".FromBase64String(" ascii wide nocase
		$s3 = "eval(System.Text.Encoding." ascii wide nocase

	condition:
		filesize <850 and all of them
}