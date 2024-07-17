rule DITEKSHEN_INDICATOR_TOOL_PET_Botb : FILE
{
	meta:
		description = "Detects Break out the Box (BOtB)"
		author = "ditekSHen"
		id = "acafa6dd-51b9-5945-b1df-7763a97a424f"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L696-L710"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "a01f796b27852f9217d9bfea32f8d9ffb3c88521d4413f6612f7a0544cf44fb3"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "to unallocated span%%!%c(*big.Float=%s), RecursionDesired: /usr/share/zoneinfo//{Bucket}/{Key+}?acl/{Bucket}?accelerate/{Bucket}?encryption/{Bucket}?" ascii
		$s2 = "exploit CVE-2019-5736 with command: [ERROR] In Enabling CGROUP Notifications -> 'echo 1 > [INFO] CGROUP may exist, attempting exploit regardless" ascii
		$s3 = "main.execShellCmd" ascii
		$s4 = "[*] Data uploaded to:[+]" ascii
		$s5 = "whitespace or line breakfailed to find credentials in the environment.failed to get %s EC2 instance role credentialsfirst" ascii
		$s6 = "This process will exit IF an EXECVE is called in the Container or if the Container is manually stoppedPerform reverse DNS lookups" ascii
		$s7 = "http: request too largehttp://100.100.100.200/http://169.254.169.254/index out of range" ascii

	condition:
		uint16(0)==0x457f and 6 of them
}