import "pe"


rule DITEKSHEN_INDICATOR_TOOL_Sqlrecon : FILE
{
	meta:
		description = "Detects SQLRecon C# MS-SQL toolkit designed for offensive reconnaissance and post-exploitation"
		author = "ditekSHen"
		id = "ec91285b-690d-5fd3-b0fc-f8d72cbb7e15"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1420-L1436"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "784dbc518cf9492557c9b3536256c4a9b03e4536cf7cee7e764b8009dd4686bb"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "ConvertDLLToSQLBytes" ascii
		$s2 = "\\SQLRecon.pdb" ascii
		$s3 = "GetAllSQLServerInfo" ascii
		$s4 = "<GetMSSQLSPNs>b__" ascii
		$s5 = "select 1; exec master..xp_cmdshell" wide
		$s6 = "-> Command Execution" wide
		$s7 = ";EXEC dbo.sp_add_jobstep @job_name =" wide
		$s8 = "EXEC sp_drop_trusted_assembly 0x" wide
		$s9 = "(&(sAMAccountType=805306368)(servicePrincipalName=MSSQL*))" wide

	condition:
		uint16(0)==0x5a4d and 5 of them
}