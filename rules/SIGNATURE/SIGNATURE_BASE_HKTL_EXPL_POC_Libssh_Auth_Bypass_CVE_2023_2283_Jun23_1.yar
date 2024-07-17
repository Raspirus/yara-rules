
rule SIGNATURE_BASE_HKTL_EXPL_POC_Libssh_Auth_Bypass_CVE_2023_2283_Jun23_1 : CVE_2023_2283 FILE
{
	meta:
		description = "Detects POC code used in attacks against libssh vulnerability CVE-2023-2283"
		author = "Florian Roth"
		id = "e72eba33-686f-5fca-bca3-2b875d1ec224"
		date = "2023-06-08"
		modified = "2023-12-05"
		reference = "https://github.com/github/securitylab/tree/1786eaae7f90d87ce633c46bbaa0691d2f9bf449/SecurityExploits/libssh/pubkey-auth-bypass-CVE-2023-2283"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_libssh_cve_2023_2283_jun23.yar#L2-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4c3d54d7f4902c1da664e41096b5931e6534aaaf63243f12e05b81af63d8b28f"
		score = 85
		quality = 85
		tags = "CVE-2023-2283, FILE"

	strings:
		$s1 = "nprocs = %d" ascii fullword
		$s2 = "fork failed: %s" ascii fullword

	condition:
		uint16(0)==0x457f and all of them
}