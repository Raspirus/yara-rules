rule ELASTIC_Windows_Hacktool_Sharpsccm_9Bef8Dab : FILE MEMORY
{
	meta:
		description = "Detects Windows Hacktool Sharpsccm (Windows.Hacktool.SharpSCCM)"
		author = "Elastic Security"
		id = "9bef8dab-af2e-46be-811a-0ac78d74a4ef"
		date = "2024-03-25"
		modified = "2024-05-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_SharpSCCM.yar#L1-L31"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2e169c4fd16627029445bb0365a2f9ee61ab6b3757b8ad02fd210ce85dc9c97f"
		logic_hash = "560c780934a63b3c857a09841c09cbc350205868c696fac958e249e1379cc865"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "dfbb7f142628eb7dc6c96dd271562d88a0970534af85464c10232ec01f58e35b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$name = "SharpSCCM" wide fullword
		$s1 = "--relay-server" wide fullword
		$s2 = "--username" wide fullword
		$s3 = "--domain" wide fullword
		$s4 = "--sms-provider" wide fullword
		$s5 = "--wmi-namespace" wide fullword
		$s6 = "--management-point" wide fullword
		$s7 = "--get-system" wide fullword
		$s8 = "--run-as-user" wide fullword
		$s9 = "--register-client" wide fullword
		$s10 = "MS_Collection" wide fullword
		$s11 = "SOFTWARE\\Microsoft\\CCM" wide fullword
		$s12 = "CCM_POST" wide fullword

	condition:
		($name and 2 of ($s*)) or 7 of ($s*)
}