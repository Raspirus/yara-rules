rule SIGNATURE_BASE_CVE_2017_8759_SOAP_Txt : CVE_2017_8759 FILE
{
	meta:
		description = "Detects malicious file in releation with CVE-2017-8759 - file exploit.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "36474420-4fa9-5264-a46b-bb2434624710"
		date = "2017-09-14"
		modified = "2023-12-05"
		reference = "https://github.com/Voulnet/CVE-2017-8759-Exploit-sample"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/exploit_cve_2017_8759.yar#L78-L92"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "184179006ed2ac2ad76e09c53196805fcb1b7380dab1d5740b4469a89d6b0b32"
		score = 75
		quality = 85
		tags = "CVE-2017-8759, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "840ad14e29144be06722aff4cc04b377364eeed0a82b49cc30712823838e2444"

	strings:
		$s1 = /<soap:address location="http[s]?:\/\/[^"]{8,140}.hta"/ ascii wide
		$s2 = /<soap:address location="http[s]?:\/\/[^"]{8,140}mshta.exe"/ ascii wide

	condition:
		( filesize <200KB and 1 of them )
}