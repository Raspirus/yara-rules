
rule SECUINFRA_OBFUS_Powershell_Replace_Tilde : FILE
{
	meta:
		description = "Detects usage of Replace to replace tilde. Often observed in obfuscation"
		author = "SECUINFRA Falcon Team"
		id = "59b68982-01ae-588a-9802-bb92c72342a8"
		date = "2022-10-02"
		modified = "2022-02-27"
		reference = "https://bazaar.abuse.ch/sample/4c391b57d604c695925938bfc10ceb4673edd64e9655759c2aead9e12b3e17cf/"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Obfuscation/powershell_obfuscation.yar#L19-L32"
		license_url = "N/A"
		logic_hash = "a2693757f9aedc1019a94a15ae00f87af852d319aa698dadd7f9bb98128622a0"
		score = 75
		quality = 70
		tags = "FILE"

	strings:
		$a = ".Replace(\"~\",\"0\")"

	condition:
		filesize <400KB and $a
}