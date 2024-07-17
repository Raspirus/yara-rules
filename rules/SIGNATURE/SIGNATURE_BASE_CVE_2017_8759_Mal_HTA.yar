
rule SIGNATURE_BASE_CVE_2017_8759_Mal_HTA : CVE_2017_8759 FILE
{
	meta:
		description = "Detects malicious files related to CVE-2017-8759 - file cmd.hta"
		author = "Florian Roth (Nextron Systems)"
		id = "e53b5149-fc94-5da5-8e35-7f09a9cd79fd"
		date = "2017-09-14"
		modified = "2023-12-05"
		reference = "https://github.com/Voulnet/CVE-2017-8759-Exploit-sample"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/exploit_cve_2017_8759.yar#L11-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f98578104e411fcf75a46f8a0bc3e561c94d0ca4ad7c1aae2595d03a29efd74e"
		score = 75
		quality = 85
		tags = "CVE-2017-8759, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "fee2ab286eb542c08fdfef29fabf7796a0a91083a0ee29ebae219168528294b5"

	strings:
		$x1 = "Error = Process.Create(\"powershell -nop cmd.exe /c" fullword ascii

	condition:
		( uint16(0)==0x683c and filesize <1KB and all of them )
}