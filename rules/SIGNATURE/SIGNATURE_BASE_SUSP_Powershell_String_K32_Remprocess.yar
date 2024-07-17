rule SIGNATURE_BASE_SUSP_Powershell_String_K32_Remprocess : FILE
{
	meta:
		description = "Detects suspicious PowerShell code that uses Kernel32, RemoteProccess handles or shellcode"
		author = "Florian Roth (Nextron Systems)"
		id = "ad646e19-b132-5594-bea2-d74e96c06ebb"
		date = "2018-03-31"
		modified = "2024-04-03"
		reference = "https://github.com/nccgroup/redsnarf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_powershell_susp.yar#L195-L215"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "03c80de8e59e640709c4ee1912dc47c398e265f9b88845a6de88031e2eb46ba3"
		score = 65
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash3 = "54a8dd78ec4798cf034c7765d8b2adfada59ac34d019e77af36dcaed1db18912"
		hash4 = "6d52cdd74edea68d55c596554f47eefee1efc213c5820d86e64de0853a4e46b3"

	strings:
		$x1 = "Throw \"Unable to allocate memory in the remote process for shellcode\"" fullword ascii
		$x2 = "$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke(\"kernel32.dll\")" fullword ascii
		$s3 = "$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants." ascii
		$s7 = "if ($RemoteProcHandle -eq [IntPtr]::Zero)" fullword ascii
		$s8 = "if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))" fullword ascii
		$s9 = "$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, " ascii
		$s15 = "$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null" fullword ascii

	condition:
		uint16(0)==0x7566 and filesize <6000KB and 1 of them
}