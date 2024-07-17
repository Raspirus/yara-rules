
rule SECUINFRA_OBFUS_Powershell_Execution : FILE
{
	meta:
		description = "Detects some variations of obfuscated PowerShell code to execute further PowerShell code"
		author = "SECUINFRA Falcon Team"
		id = "b32c2a92-599c-5916-a335-dc996dcdc1bf"
		date = "2022-09-02"
		modified = "2022-02-27"
		reference = "https://github.com/SIFalcon/Detection"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Obfuscation/powershell_obfuscation.yar#L1-L17"
		license_url = "N/A"
		logic_hash = "b201774edc4a20a0035cd68898a785a6c2fc03fb8739d515196e428d4a88af70"
		score = 75
		quality = 70
		tags = "FILE"

	strings:
		$a1 = "-nop -w hiddEn -Ep bypass -Enc" ascii nocase
		$a2 = "-noP -sta -w 1 -enc" ascii nocase
		$b1 = "SQBFAF"

	condition:
		filesize <300KB and $b1 and 1 of ($a*)
}