import "pe"


import "pe"


rule ESET_Apt_Windows_Invisimole_DNS_Downloader : FILE
{
	meta:
		description = "InvisiMole DNS downloader"
		author = "ESET Research"
		id = "1caa6c8b-3798-556e-835e-885b7f3f4511"
		date = "2021-05-17"
		modified = "2021-05-17"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/invisimole/invisimole.yar#L140-L170"
		license_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/LICENSE"
		logic_hash = "88d6ed7ec1331153d19afc18473a4be2b214ad8af29fcf7051a2a8e40e088231"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$d = "DnsQuery_A"
		$s1 = "Wireshark-is-running-{9CA78EEA-EA4D-4490-9240-FC01FCEF464B}" xor
		$s2 = "AddIns\\" ascii wide xor
		$s3 = "pcornomeex." xor
		$s4 = "weriahsek.rxe" xor
		$s5 = "dpmupaceex." xor
		$s6 = "TCPViewClass" xor
		$s7 = "PROCMON_WINDOW_CLASS" xor
		$s8 = "Key%C"
		$s9 = "AutoEx%C" xor
		$s10 = "MSO~"
		$s11 = "MDE~"
		$s12 = "DNS PLUGIN, Step %d" xor
		$s13 = "rundll32.exe \"%s\",StartUI"

	condition:
		(( uint16(0)==0x5A4D) or ESET_Invisimole_Blob_PRIVATE) and $d and 5 of ($s*)
}