
rule SECUINFRA_MAL_Nw0Rm : FILE
{
	meta:
		description = "Detect the final RAT dropped by N-W0rm"
		author = "SECUINFRA Falcon Team"
		id = "b014ce63-33ec-51df-a529-0c197dac2d7a"
		date = "2022-03-02"
		modified = "2022-02-07"
		reference = "https://www.secuinfra.com/en/techtalk/n-w0rm-analysis-part-2/"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/RAT/n-w0rm.yar#L1-L24"
		license_url = "N/A"
		hash = "08587e04a2196aa97a0f939812229d2d"
		logic_hash = "04078c57c1aa0065fceec7dc92b201bda23de1c5f5a940803a81250bdd685736"
		score = 75
		quality = 70
		tags = "FILE"

	strings:
		$a1 = "N-W0rm" fullword wide
		$a2 = "N_W0rm" fullword wide
		$a3 = "|NW|" fullword wide
		$b1 = "Select * from AntivirusProduct" fullword wide
		$b2 = "ExecutionPolicy Bypass -WindowStyle Hidden -NoExit -File" fullword wide
		$b3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36" fullword wide
		$b4 = "killer" fullword wide
		$b5 = "nyanmoney02.duckdns.org" fullword wide

	condition:
		uint16(0)==0x5a4d and 2 of ($a*) and 2 of ($b*)
}