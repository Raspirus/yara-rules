
rule ELASTIC_Windows_Trojan_Agenttesla_D3Ac2B2F : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Agenttesla (Windows.Trojan.AgentTesla)"
		author = "Elastic Security"
		id = "d3ac2b2f-14fc-4851-8a57-41032e386aeb"
		date = "2021-03-22"
		modified = "2022-06-20"
		reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_AgentTesla.yar#L1-L58"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "65463161760af7ab85f5c475a0f7b1581234a1e714a2c5a555783bdd203f85f4"
		logic_hash = "9c13a99107593d476de1522ced10aa43d34535b844e8c3ae871b22358137c926"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "cbbb56fe6cd7277ae9595a10e05e2ce535a4e6bf205810be0bbce3a883b6f8bc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "GetMozillaFromLogins" ascii fullword
		$a2 = "AccountConfiguration+username" wide fullword
		$a3 = "MailAccountConfiguration" ascii fullword
		$a4 = "KillTorProcess" ascii fullword
		$a5 = "SmtpAccountConfiguration" ascii fullword
		$a6 = "GetMozillaFromSQLite" ascii fullword
		$a7 = "Proxy-Agent: HToS5x" wide fullword
		$a8 = "set_BindingAccountConfiguration" ascii fullword
		$a9 = "doUsernamePasswordAuth" ascii fullword
		$a10 = "SafariDecryptor" ascii fullword
		$a11 = "get_securityProfile" ascii fullword
		$a12 = "get_useSeparateFolderTree" ascii fullword
		$a13 = "get_DnsResolver" ascii fullword
		$a14 = "get_archivingScope" ascii fullword
		$a15 = "get_providerName" ascii fullword
		$a16 = "get_ClipboardHook" ascii fullword
		$a17 = "get_priority" ascii fullword
		$a18 = "get_advancedParameters" ascii fullword
		$a19 = "get_disabledByRestriction" ascii fullword
		$a20 = "get_LastAccessed" ascii fullword
		$a21 = "get_avatarType" ascii fullword
		$a22 = "get_signaturePresets" ascii fullword
		$a23 = "get_enableLog" ascii fullword
		$a24 = "TelegramLog" ascii fullword
		$a25 = "generateKeyV75" ascii fullword
		$a26 = "set_accountName" ascii fullword
		$a27 = "set_InternalServerPort" ascii fullword
		$a28 = "set_bindingConfigurationUID" ascii fullword
		$a29 = "set_IdnAddress" ascii fullword
		$a30 = "set_GuidMasterKey" ascii fullword
		$a31 = "set_username" ascii fullword
		$a32 = "set_version" ascii fullword
		$a33 = "get_Clipboard" ascii fullword
		$a34 = "get_Keyboard" ascii fullword
		$a35 = "get_ShiftKeyDown" ascii fullword
		$a36 = "get_AltKeyDown" ascii fullword
		$a37 = "get_Password" ascii fullword
		$a38 = "get_PasswordHash" ascii fullword
		$a39 = "get_DefaultCredentials" ascii fullword

	condition:
		8 of ($a*)
}