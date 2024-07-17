
rule SIGNATURE_BASE_APT_UTA028_Forensicartefacts_Paloalto_CVE_2024_3400_Apr24_1 : SCRIPT CVE_2024_3400
{
	meta:
		description = "Detects forensic artefacts of APT UTA028 as found in a campaign exploiting the Palo Alto CVE-2024-3400 vulnerability"
		author = "Florian Roth"
		id = "32cf18ff-784d-5849-87f8-14ede7315188"
		date = "2024-04-15"
		modified = "2024-04-18"
		reference = "https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/vuln_paloalto_cve_2024_3400_apr24.yar#L2-L25"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1261eecca520daa0619859a45d2289d2c23c73be55e1a3849d2032a38e137f4d"
		score = 70
		quality = 85
		tags = "SCRIPT, CVE-2024-3400"

	strings:
		$x1 = "cmd = base64.b64decode(rst.group"
		$x2 = "f.write(\"/*\"+output+\"*/\")"
		$x3 = "* * * * * root wget -qO- http://"
		$x4 = "rm -f /var/appweb/sslvpndocs/global-protect/*.css"
		$x5a = "failed to unmarshal session(../"
		$x5b = "failed to unmarshal session(./../"
		$x6 = "rm -rf /opt/panlogs/tmp/device_telemetry/minute/*" base64
		$x7 = "$(uname -a) > /var/" base64

	condition:
		1 of them
}