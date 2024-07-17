
rule ELASTIC_Windows_Hacktool_Sharpwmi_A67D6Fe5 : FILE MEMORY
{
	meta:
		description = "Detects Windows Hacktool Sharpwmi (Windows.Hacktool.SharpWMI)"
		author = "Elastic Security"
		id = "a67d6fe5-3ce5-4e63-979e-3fb799d9d173"
		date = "2022-10-20"
		modified = "2022-11-24"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_SharpWMI.yar#L1-L27"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2134a5e1a5eece1336f831a7686c5ea3b6ca5aaa63ab7e7820be937da0678e15"
		logic_hash = "de8749951ece8d4798ade4661d531515e12edf8e8606ddc330000d847a66a26c"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "20719ea15d4dee90c95b474689752172a6b6fb941dced81803f9f726ddc26d29"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$guid = "6DD22880-DAC5-4B4D-9C91-8C35CC7B8180" ascii wide nocase
		$str0 = "powershell -w hidden -nop -c \"$e=([WmiClass]'{0}:{1}').Properties['{2}'].Value;[IO.File]::WriteAllBytes('{3}',[Byte[]][Int[]]($e-split','))\"" ascii wide
		$str1 = "powershell -w hidden -nop -c \"iex($env:{0})\"" ascii wide
		$str2 = "SELECT * FROM Win32_Process" ascii wide
		$str3 = "DOWNLOAD_URL" ascii wide
		$str4 = "TARGET_FILE" ascii wide
		$str5 = "SELECT Enabled,DisplayName,Action,Direction,InstanceID from MSFT_NetFirewallRule WHERE Enabled=1" ascii wide
		$print_str0 = "This may indicate called SharpWMI did not invoked WMI using elevated/impersonated token." ascii wide
		$print_str1 = "[+] Attempted to terminate remote process ({0}). Returned: {1}" ascii wide

	condition:
		$guid or ( all of ($str*) and 1 of ($print_str*))
}