
rule ELASTIC_Windows_Trojan_Trickbot_Dcf25Dde : FILE MEMORY
{
	meta:
		description = "Targets networkDll64.dll module containing functionality to gather network and system information"
		author = "Elastic Security"
		id = "dcf25dde-36c4-4a24-aa2b-0b3f42324918"
		date = "2021-03-29"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L461-L502"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ba2a255671d33677cab8d93531eb25c0b1f1ac3e3085b95365a017463662d787"
		logic_hash = "64d15d92faf0919a8fa1ce6772750cde47eaa24b09cf4243393777334bad9712"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "4088ae29cb3b665ccedf69e9d02c1ff58620d4b589343cd4077983b25c5b479f"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "Host Name - %s" wide fullword
		$a2 = "Last Boot Up Time - %02u/%02u/%04u %02d.%02d.%02d" wide fullword
		$a3 = "Install Date - %02u/%02u/%04u %02d.%02d.%02d" wide fullword
		$a4 = "System Directory - %s" wide fullword
		$a5 = "OS Version - %s" wide fullword
		$a6 = "***PROCESS LIST***" wide fullword
		$a7 = "Product Type - Domain Controller" wide fullword
		$a8 = "Registered Organization - %s" wide fullword
		$a9 = "Product Type - Domain Controller" wide fullword
		$a10 = "Build Type - %s" wide fullword
		$a11 = "Boot Device - %s" wide fullword
		$a12 = "Serial Number - %s" wide fullword
		$a13 = "OS Architecture - %s" wide fullword
		$a14 = "<moduleconfig><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"SetConf\" file=\"dpost\" period=\"1440\"/></au"
		$a15 = "oduleconfig>" ascii fullword
		$a16 = "Computer name: %s" wide fullword
		$a17 = "/c net view /all /domain" ascii fullword
		$a18 = "/c nltest /domain_trusts" ascii fullword
		$a19 = "***SYSTEMINFO***" wide fullword
		$a20 = "***LOCAL MACHINE DATA***" wide fullword
		$a21 = "Admin Name: %s" wide fullword
		$a22 = "Domain controller: %s" wide fullword
		$a23 = "Admin E-mail: %s" wide fullword

	condition:
		4 of ($a*)
}