rule SIGNATURE_BASE_MAL_ELF_Torchtriton : FILE
{
	meta:
		description = "Detection for backdoor (TorchTriton) distributed with a nightly build of PyTorch"
		author = "Silas Cutler"
		id = "85e98ee7-30bf-554f-a0ac-9df263e6dfe4"
		date = "2023-01-02"
		modified = "2023-12-05"
		reference = "https://www.bleepingcomputer.com/news/security/pytorch-discloses-malicious-dependency-chain-compromise-over-holidays/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_100days_of_yara_2023.yar#L88-L117"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "2385b29489cd9e35f92c072780f903ae2e517ed422eae67246ae50a5cc738a0e"
		logic_hash = "12de3c3785aaf3623097db58abfe8ee2cbd9a0e712bf752165952de9a5fdb07d"
		score = 75
		quality = 85
		tags = "FILE"
		version = "1.0"
		DaysofYARA = "2/100"

	strings:
		$error = "failed to send packet"
		$aes_key = "gIdk8tzrHLOM)mPY-R)QgG[;yRXYCZFU"
		$aes_iv = "?BVsNqL]S.Ni"
		$func01 = "splitIntoDomains("
		$func02 = "packageForTransport"
		$func03 = "gatherFiles"
		$func04 = "void sendFile("
		$domain = "&z-%`-(*"

	condition:
		uint32(0)==0x464c457f and (( all of ($aes_*)) or ( all of ($func*) and $error) or ($domain and 2 of them ))
}