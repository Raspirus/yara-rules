import "pe"


rule DITEKSHEN_INDICATOR_TOOL_Sharpldap : FILE
{
	meta:
		description = "Detects SharpLDAP tool written in C# that aims to do enumeration via LDAP queries"
		author = "ditekSHen"
		id = "597e578d-41f0-595e-b92c-0c3676d8b47a"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1724-L1739"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "da5db3f2907229dc68e3c6f3351361a4b1fb9fe8afc597c9dfe611f9725c6181"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$x1 = "SharpLDAP" ascii wide
		$x2 = "SharpLDAP.pdb" ascii
		$s1 = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" wide
		$s2 = "(&(servicePrincipalName=*))" wide
		$s3 = "/Enumerating (Domain|Enterprise|Organizational|Service|Members|Users|Computers)/" wide
		$s4 = "ListMembers" fullword ascii
		$s5 = "GroupMembers" fullword ascii
		$s6 = "get_SamAccountName" fullword ascii

	condition:
		uint16(0)==0x5a4d and ((1 of ($x*) and 4 of ($s*)) or (5 of ($s*)))
}