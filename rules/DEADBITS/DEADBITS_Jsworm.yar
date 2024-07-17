
rule DEADBITS_Jsworm : MALWARE FILE
{
	meta:
		description = "No description has been set in the source file - DeadBits"
		author = "Adam Swanda"
		id = "6d452d04-b475-5241-890c-68119a7a8691"
		date = "2019-09-06"
		modified = "2019-09-06"
		reference = "https://github.com/deadbits/yara-rules/"
		source_url = "https://github.com/deadbits/yara-rules//blob/d002f7ecee23e09142a3ac3e79c84f71dda3f001/rules/JSWorm.yara#L1-L38"
		license_url = "N/A"
		logic_hash = "99074e25ec15c5b25fa41bef19203f5ddc227acd51fadca1e2c3ece538b3da01"
		score = 75
		quality = 78
		tags = "MALWARE, FILE"

	strings:
		$name00 = "JSWORM" nocase
		$str00 = "DECRYPT.txt" nocase
		$str02 = "cmd.exe"
		$str03 = "/c reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v \"zapiska\" /d \"C:\\ProgramData\\"
		$str04 = /\/c taskkill.exe taskkill \/f \/im (store|sqlserver|dns|sqlwriter)\.exe/
		$str05 = "/c start C:\\ProgramData\\"
		$str06 = "/c vssadmin.exe delete shadows /all /quiet"
		$str07 = "/c bcdedit /set {default} bootstatuspolicy ignoreallfailures -y"
		$str08 = "/c bcdedit /set {default} recoveryenabled No -y"
		$str09 = "/c wbadmin delete catalog -quiet"
		$str10 = "/c wmic shadowcopy delete -y"
		$uniq00 = "fuckav"
		$uniq01 = "DECRYPT.hta" nocase
		$uniq02 = "Backup e-mail for contact :"
		$uniq03 = "<HTA:APPLICATION APPLICATIONNAME=" nocase

	condition:
		uint16(0)==0x5a4d and (($name00 and 5 of ($str*)) or (5 of ($str*) and 2 of ($uniq*)) or ($name00 and any of ($uniq*)))
}