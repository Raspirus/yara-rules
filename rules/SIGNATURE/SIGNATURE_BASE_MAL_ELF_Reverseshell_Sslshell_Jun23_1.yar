
rule SIGNATURE_BASE_MAL_ELF_Reverseshell_Sslshell_Jun23_1 : CVE_2023_2868 FILE
{
	meta:
		description = "Detects reverse shell named SSLShell used in Barracuda ESG exploitation (CVE-2023-2868)"
		author = "Florian Roth"
		id = "91b34eb7-61d2-592e-a444-249da43994ca"
		date = "2023-06-07"
		modified = "2023-12-05"
		reference = "https://www.barracuda.com/company/legal/esg-vulnerability"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/mal_lnx_barracuda_cve_2023_2868.yar#L2-L19"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "57e9afb2f6928656242b8257cc3b98ae3b03e38c75ad40b544e3fc6afaea794d"
		score = 75
		quality = 85
		tags = "CVE-2023-2868, FILE"
		hash1 = "8849a3273e0362c45b4928375d196714224ec22cb1d2df5d029bf57349860347"

	strings:
		$sc1 = { 00 2D 63 00 2F 62 69 6E 2F 73 68 00 }
		$s1 = "SSLShell"

	condition:
		uint32be(0)==0x7f454c46 and uint16(0x10)==0x0002 and filesize <5MB and all of them
}