
rule SIGNATURE_BASE_Hiddencobra_BANKSHOT_Gen : FILE
{
	meta:
		description = "Detects Hidden Cobra BANKSHOT trojan"
		author = "Florian Roth (Nextron Systems)"
		id = "fbf9dd32-cb9a-51f2-bd03-0387fbf44baa"
		date = "2017-12-26"
		modified = "2022-06-10"
		reference = "https://www.us-cert.gov/HIDDEN-COBRA-North-Korean-Malicious-Cyber-Activity"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_hiddencobra_bankshot.yar#L11-L63"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "db4d396736ab42942f1a11a819419410e388b011e8992ad187c2f484d637c99c"
		score = 75
		quality = 83
		tags = "FILE"
		hash1 = "89775a2fbb361d6507de6810d2ca71711d5103b113179f1e1411ccf75e6fc486"
		hash2 = "8b2d084a8bb165b236d3e5436d6cb6fa1fda6431f99c4f34973dc735b4f2d247"
		hash3 = "b766ee0f46c92a746f6db3773735ee245f36c1849de985bbc3a37b15f7187f24"
		hash4 = "daf5facbd67f949981f8388a6ca38828de2300cb702ad530e005430782802b75"
		hash5 = "ef6f8b43caa25c5f9c7749e52c8ab61e8aec8053b9f073edeca4b35312a0a699"
		hash6 = "d900ee8a499e288a11f1c75e151569b518864e14c58cc72c47f95309956b3eff"
		hash7 = "ec44ecd57401b3c78d849115f08ff046011b6eb933898203b7641942d4ee3af9"
		hash8 = "3e6d575b327a1474f4767803f94799140e16a729e7d00f1bea40cd6174d8a8a6"
		hash9 = "6db37a52517653afe608fd84cc57a2d12c4598c36f521f503fd8413cbef9adca"

	strings:
		$s1 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)" fullword wide
		$s2 = "rHTTP/1.1 200 Connection established" fullword wide
		$s3 = "Proxy-Connection: keep-alive" fullword wide
		$s4 = "\\msncf.dat" wide
		$s5 = "msvcru32.bat" fullword ascii
		$s6 = "reg delete \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"%s\" /f" fullword ascii
		$s7 = "MXINFO.DLL" fullword ascii
		$s8 = "usrvc32.bat" fullword ascii
		$s9 = "ping -n 1 127.0.0.1" fullword ascii
		$s10 = "%sd.e%sc \"%s > %s 2>&1\"" ascii fullword
		$s11 = "DWS*.tmp" ascii fullword
		$s12 = "CS*.tmp" fullword wide
		$s13 = "WM*.tmp" fullword wide
		$x1 = "CgpaipIddwspwe32Hnaehsdi" fullword ascii
		$x2 = "RpiPmtiCdopIsgpao" fullword ascii
		$x3 = "RpiLtnodlhOtgpcidgyA" fullword ascii
		$x4 = "LatiQdgHtnrwpDbupci" fullword ascii
		$x6 = "\\system32\\msncf.dat" ascii
		$x7 = "GprthipgHpgktcpCigwSanowpgA" fullword ascii
		$a1 = "live.dropbox.com" fullword ascii
		$a2 = "tatadocomo.yahoo.com" fullword ascii
		$a3 = "widgets.twimg.com" fullword ascii
		$a4 = "history.paypal.com" fullword ascii
		$a5 = "www.bitcoin.org" fullword ascii
		$a6 = "web.whatsapp.com" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <500KB and (1 of ($x*) or 2 of ($s*) or 4 of ($a*))
}