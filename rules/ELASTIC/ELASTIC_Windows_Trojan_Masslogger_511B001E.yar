rule ELASTIC_Windows_Trojan_Masslogger_511B001E : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Masslogger (Windows.Trojan.MassLogger)"
		author = "Elastic Security"
		id = "511b001e-dc67-4e45-9096-0b01101ca0ab"
		date = "2022-03-02"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_MassLogger.yar#L1-L24"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "177875c756a494872c516000beb6011cec22bd9a73e58ba6b2371dba2ab8c337"
		logic_hash = "5abac5e32e55467710842e19c25cab5c7f1cdb0f8a68fb6808d54467c69ebdf6"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "14ec9c32af7c1dd4a1f73e37ef9e042c18d9e0179b0e5732752767f93be6d4e2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "ExecutionPolicy Bypass -WindowStyle Hidden -Command netsh advfirewall firewall add rule name='allow RemoteDesktop' dir=in protoc" wide
		$a2 = "https://raw.githubusercontent.com/lisence-system/assemply/main/VMprotectEncrypt.jpg" wide fullword
		$a3 = "ECHO $SMTPServer  = smtp.gmail.com >> %PSScript%" wide fullword
		$a4 = "Injecting Default Template...." wide fullword
		$a5 = "GetVncLoginMethodAsync" ascii fullword
		$a6 = "/c start computerdefaults.exe" wide fullword

	condition:
		all of them
}