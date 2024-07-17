
rule BINARYALERT_Hacktool_Windows_Cobaltstrike_Powershell : FILE
{
	meta:
		description = "Detection of the PowerShell payloads from Cobalt Strike"
		author = "@javutin, @joseselvi"
		id = "155f181a-56cb-5295-a903-744f79012733"
		date = "2017-12-14"
		modified = "2017-12-14"
		reference = "https://www.cobaltstrike.com/help-payload-generator"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/windows/hacktool_windows_cobaltstrike_powershell.yara#L1-L21"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "39dd0aaa84d02aae5766d764c3d371f03f9df33acf5f6ae4ab4a8c73dd827213"
		score = 75
		quality = 80
		tags = "FILE"

	strings:
		$ps1 = "Set-StrictMode -Version 2"
		$ps2 = "func_get_proc_address"
		$ps3 = "func_get_delegate_type"
		$ps4 = "FromBase64String"
		$ps5 = "VirtualAlloc"
		$ps6 = "var_code"
		$ps7 = "var_buffer"
		$ps8 = "var_hthread"

	condition:
		$ps1 at 0 and filesize <1000KB and all of ($ps*)
}