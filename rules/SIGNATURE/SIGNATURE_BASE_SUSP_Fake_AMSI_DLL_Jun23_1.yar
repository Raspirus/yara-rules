import "pe"


rule SIGNATURE_BASE_SUSP_Fake_AMSI_DLL_Jun23_1 : FILE
{
	meta:
		description = "Detects an amsi.dll that has the same exports as the legitimate one but very different contents or file sizes"
		author = "Florian Roth"
		id = "b12df9de-ecfb-562b-b599-87fa786a33bc"
		date = "2023-06-07"
		modified = "2023-06-12"
		reference = "https://twitter.com/eversinc33/status/1666121784192581633?s=20"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_fake_amsi_dll.yar#L3-L35"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ec3db233ab22144bc65614b45bb894a7ea5a4fd40ccb603e6e52cc1b9ff8805b"
		score = 65
		quality = 85
		tags = "FILE"

	strings:
		$a1 = "Microsoft.Antimalware.Scan.Interface" ascii
		$a2 = "Amsi.pdb" ascii fullword
		$a3 = "api-ms-win-core-sysinfo-" ascii
		$a4 = "Software\\Microsoft\\AMSI\\Providers" wide
		$a5 = "AmsiAntimalware@" ascii
		$a6 = "AMSI UAC Scan" ascii
		$fp1 = "Wine builtin DLL"

	condition:
		uint16(0)==0x5a4d and (pe.exports("AmsiInitialize") and pe.exports("AmsiScanString")) and ( filesize >200KB or filesize <35KB or not 4 of ($a*)) and not 1 of ($fp*)
}