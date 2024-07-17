rule SIGNATURE_BASE_EXPL_Paloalto_CVE_2024_3400_Apr24_1 : CVE_2024_3400
{
	meta:
		description = "Detects characteristics of the exploit code used in attacks against Palo Alto GlobalProtect CVE-2024-3400"
		author = "Florian Roth"
		id = "1bcf0415-5351-5e09-ab93-496e8dc47c92"
		date = "2024-04-15"
		modified = "2024-04-24"
		reference = "https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/vuln_paloalto_cve_2024_3400_apr24.yar#L27-L46"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "9ebc94a07b189a2d2dd252b5079fa494162739678fd2ca742e6877189a140da9"
		score = 70
		quality = 85
		tags = "CVE-2024-3400"

	strings:
		$x1 = "SESSID=../../../../opt/panlogs/"
		$x2 = "SESSID=./../../../../opt/panlogs/"
		$sa1 = "SESSID=../../../../"
		$sa2 = "SESSID=./../../../../"
		$sb2 = "${IFS}"

	condition:
		1 of ($x*) or (1 of ($sa*) and $sb2)
}