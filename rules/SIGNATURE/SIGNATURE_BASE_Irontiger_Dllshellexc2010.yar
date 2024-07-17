rule SIGNATURE_BASE_Irontiger_Dllshellexc2010 : FILE
{
	meta:
		description = "dllshellexc2010 Exchange backdoor + remote shell"
		author = "Cyber Safety Solutions, Trend Micro"
		id = "960e8e5c-65a5-5dd2-90fa-1f7d31ee8cb5"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "http://goo.gl/T5fSJC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_irontiger_trendmicro.yar#L48-L63"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b75477f01627ac05013c5e4ccb1d58a6bb25bfbe83ad0cec392140d44637a028"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$str1 = "Microsoft.Exchange.Clients.Auth.dll" ascii wide
		$str2 = "Dllshellexc2010" wide ascii
		$str3 = "Users\\ljw\\Documents" wide ascii
		$bla1 = "please input path" wide ascii
		$bla2 = "auth.owa" wide ascii

	condition:
		( uint16(0)==0x5a4d) and (( any of ($str*)) or ( all of ($bla*)))
}