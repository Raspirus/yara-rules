rule SIGNATURE_BASE_CVE_2017_8759_Mal_Doc : CVE_2017_8759 FILE
{
	meta:
		description = "Detects malicious files related to CVE-2017-8759 - file Doc1.doc"
		author = "Florian Roth (Nextron Systems)"
		id = "48587c13-7661-5987-8331-732115f7823b"
		date = "2017-09-14"
		modified = "2023-11-21"
		reference = "https://github.com/Voulnet/CVE-2017-8759-Exploit-sample"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/exploit_cve_2017_8759.yar#L26-L45"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0c81feebef463fee41661ca951a39ee789db5d36acc8262ddb391609d8680108"
		score = 75
		quality = 85
		tags = "CVE-2017-8759, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "6314c5696af4c4b24c3a92b0e92a064aaf04fd56673e830f4d339b8805cc9635"

	strings:
		$s1 = "soap:wsdl=http://" ascii wide
		$s2 = "soap:wsdl=https://" ascii wide
		$s3 = "soap:wsdl=http%3" ascii wide
		$s4 = "soap:wsdl=https%3" ascii wide
		$c1 = "Project.ThisDocument.AutoOpen" fullword wide

	condition:
		uint16(0)==0xcfd0 and filesize <500KB and (1 of ($s*) and $c1)
}