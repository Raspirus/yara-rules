rule SIGNATURE_BASE_Turla_Png_Reg_Enum_Payload : FILE
{
	meta:
		description = "Payload that has most recently been dropped by the Turla PNG Dropper"
		author = "Ben Humphrey"
		id = "413bb315-3c01-56ab-92db-00342a11438a"
		date = "2018-11-23"
		modified = "2023-12-05"
		reference = "https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/november/turla-png-dropper-is-back/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_turla_png_dropper_nov18.yar#L51-L77"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b01d0c3a26ce955570ed5607514906bd8860f36637957e39a15f74a7dbb1a1e6"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "fea27eb2e939e930c8617dcf64366d1649988f30555f6ee9cd09fe54e4bc22b3"

	strings:
		$crypt00 = "Microsoft Software Key Storage Provider" wide
		$crypt01 = "ChainingModeCBC" wide

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and pe.imports("advapi32.dll","StartServiceCtrlDispatcherA") and pe.imports("advapi32.dll","RegEnumValueA") and pe.imports("advapi32.dll","RegEnumKeyExA") and pe.imports("ncrypt.dll","NCryptOpenStorageProvider") and pe.imports("ncrypt.dll","NCryptEnumKeys") and pe.imports("ncrypt.dll","NCryptOpenKey") and pe.imports("ncrypt.dll","NCryptDecrypt") and pe.imports("ncrypt.dll","BCryptGenerateSymmetricKey") and pe.imports("ncrypt.dll","BCryptGetProperty") and pe.imports("ncrypt.dll","BCryptDecrypt") and pe.imports("ncrypt.dll","BCryptEncrypt") and all of them
}