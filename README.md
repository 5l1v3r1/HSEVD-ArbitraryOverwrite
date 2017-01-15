```
    __  __           __   _____           
   / / / /___ ______/ /__/ ___/__  _______
  / /_/ / __ `/ ___/ //_/\__ \/ / / / ___/
 / __  / /_/ / /__/ ,<  ___/ / /_/ (__  ) 
/_/ /_/\__,_/\___/_/|_|/____/\__, /____/  
                            /____/        
			Extreme Vulnerable Driver
							Exploits
```

### HackSys Extreme Vulnerable Driver - ArbitraryOverwrite Exploit

Arbitrary Overwrite exploit; which exploits a vulnerable function within the HEVD Kernel driver and let us overwrite arbitrary data within Kernelland.

# How does this exploit work:

* First allocate a RWX memory page in which we host our Shellcode.
* Copy our Token Stealing Shellcode into the executable memory page and create a new pointer (double pointer) which points to our Payload address. This is necessary because the vulnerable function dereferences a double pointer. 
* Get a Handle to the HacksysExtremeVulnerableDriver device.
* Now we need to find the memory address of the HalDispatchTable (+ 4 Bytes) in Kernelland which we want to overwrite with the double pointer to our Payload.   
* To do this, we use the undocumented NtQuerySystemInformation() function within ntdll.dll (Native API) to find the Base address of the running kernel image and load the same kernel image in Userland, so we can calculate the address of the HalDispatchTable.
* Our write target in Kernelland will be the address of nt!HalDispatchTable+4, which will be called when we run the NtQueryIntervalProfile() function from Userland (KeQueryIntervalProfile() syscall in Kernelland).
* Now that we have both addresses, we can construct a Arbitrary Overwrite buffer and use the DeviceIoControl() function with the IOCTL code of our device/function to send the buffer to the driver in Kernelspace.
* Then we run the NtQueryIntervalProfile() function to trigger Payload execution in Kernelland and let the Shellcode replace the token handle of the exploit process with the token handle of PID 4. 
* Finally we create a new cmd.exe process using this System Token which pops us a System shell ;) 

Runs on:

```
This exploits only works on Windows 7 x86 SP1 (Version 6.1.7601).
``` 

Compile Exploit:

```
This project is written in C and can be compiled within Visual Studio.
```

Load Vulnerable Driver:

```
The HEVD driver can be downloaded from the HackSys Team Github page and loaded with the OSR Driver loader utility.
```
