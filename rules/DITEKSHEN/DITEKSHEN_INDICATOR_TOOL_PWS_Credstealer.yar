rule DITEKSHEN_INDICATOR_TOOL_PWS_Credstealer : FILE
{
	meta:
		description = "Detects Python executable for stealing credentials including domain environments. Observed in MuddyWater."
		author = "ditekSHen"
		id = "ab587b12-f3e1-5f08-b27c-03ee9752e513"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L22-L41"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "e729c8b0b1db642acabbc4590833c05ce81447bb89e5f40aea5f0b8ebdee4438"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "PYTHON27.DLL" fullword wide
		$s2 = "C:\\Python27\\lib\\site-packages\\py2exe\\boot_common.pyR" fullword ascii
		$s3 = "C:\\Python27\\lib\\site-packages\\py2exe\\boot_common.pyt" fullword ascii
		$s4 = "subprocess.pyc" fullword ascii
		$s5 = "MyGetProcAddress(%p, %p(%s)) -> %p" fullword ascii
		$p1 = "Dump SAM hashes from target systemss" fullword ascii
		$p2 = "Dump LSA secrets from target systemss" fullword ascii
		$p3 = "Dump the NTDS.dit from target DCs using the specifed method" fullword ascii
		$p4 = "Dump NTDS.dit password historys" fullword ascii
		$p5 = "Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameterss" fullword ascii
		$p6 = "Retrieve plaintext passwords and other information for accounts pushed through Group Policy Preferencess" fullword ascii
		$p7 = "Combo file containing a list of domain\\username:password or username:password entriess" fullword ascii

	condition:
		uint16(0)==0x5a4d and (3 of ($s*) and 1 of ($p*))
}