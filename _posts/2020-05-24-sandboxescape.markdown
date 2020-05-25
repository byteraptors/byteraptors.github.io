---
layout: post
title:  "Chronicles of a Sandbox Escape: Deep Analysis of CVE-2019-0880"
date:   2020-05-24 17:00:38 +0200
categories: Windows Exploitation
---

# Overview

This post describes an exploitable arbitrary pointer dereference vulnerability in splwow64.exe. This vulnerability can be triggered from the Internet Explorer Renderer process and allows a Sandbox Escape.

The vulnerability allows to arbitrarily write to the address space of splwow64.exe from a Low Integrity process by crafting specific LPC messages to the splwow64.exe process.

The vulnerability  has been tested on both a Windows 7 x64 and Windows 10 x64 machine.

In this post I will describe where the vulnerability lies and how to exploit it to achieve a full working Sandbox Escape from the Internet Explorer Sandbox.

The vulnerability seems not to be patched on Windows 7 and for this reason I will not publish the source code to exploit it.



## The bug

The bug lies in the handling of a specific LPC call to the splwow64.exe process which enables to call the memcpy function in splwow64 address space with arbitrary parameters. This gives an attacker an extremely powerful primitive since it allows to write in the memory of a higher integrity process and escape the browser Sandbox without the need to rely on a Kernel Exploit.


## The splwow64.exe process

Splwow64.exe is a Microsoft executable which gets executed every time a 32-bit application is accessing one of your installed printers.
This process is particularly interesting since it is one of the Internet Explorer Elevation Policy whitelisted processes. In other words, any call from a Low Integrity IE renderer process to spawn this process will result in splwow64.exe being loaded as a Medium Integrity process.

Before delving into the analysis of the vulnerability itself, let’s try to get a high level understanding of how the Splwow64 process actually works.


#### LPC Port Creation

After starting execution the splwow64.exe will create a LPC port by calling the ZwCreatePort API and will start waiting for incoming connections.

Let’s have a look at the ZwCreatePort function.


{% highlight c %}
NTSTATUS NTAPI ZwCreatePort(PHANDLE,POBJECT_ATTRIBUTES,ULONG,ULONG,ULONG);

{% endhighlight %}

As you can see, the second parameter is a pointer to an Object Attributes structure which will point to a UNICODE_STRING function containing the name of the LPC port created by the process.

The first thing we need to understand in order to connect to this LPC port is how the LPC port name is generated!
If you’ll inspect the Object Attributes pointer parameter to ZwCreatePort multiple times (each time after rebooting the machine), you will notice that a part of the LPC port name will change after every reboot.

The LPC port name looks like this:

<b> On Windows 10 </b>
{% highlight c %}
\\RPC Control\\UmpdProxy_1_VARIABLEPART_0_2000
{% endhighlight %}


<b> On Windows 7 </b>
{% highlight c %}
\\RPC Control\\UmpdProxy_1_VARIABLEPART_0_0
{% endhighlight %}

The VARIABLEPART will change after every reboot of the machine.

This implies that to be able to actually connect to this LPC port from the IE Sandboxed process we will need to understand how to generate the LPC port name.

Luckily for us, the algorithm to generate the variable part of the LPC port name is pretty trivial and will look like this:

- Call the OpenProcessToken API passing as parameter a handle to the current process.
- Call the GetTokenInformation API passing TokenStatistics as TOKEN_INFORMATION_CLASS
- Access the AuthenticationId.LowPart field of the newly obtained TOKEN_STATISTICS structure and convert it to a hex string.


Congratulations! You are now able to connect to the LPC port!


#### LPC Messages handling

We will now need to understand how LPC messages are parsed by the splwow64 process.
Since a full explanation of the inner workings of the splwow64 process is beyond the scope of this article, we will just focus on the bigger picture to gain enough knowledge about the vulnerability itself and its exploitation.

In a nutshell, the splwow64 will parse the incoming LPC messages in this way:
- It will accept only incoming messages having a length of 0x20 bytes.
- It will pass three pointers located at offset 0x30, 0x38 and 0x40 of the LPC message as parameters to the GdiPrinterThunk function.

This implies that as long as the sent message is 0x20 bytes long, we will be able to call the GdiPrinterThunk function with arbitrary parameters!

Sounds good! We will now need to understand how the GdiPrinterThunk actually works to see whether we can trigger something interesting by controlling the function parameters.


#### The GdiPrinterThunk function

The GdiPrinterThunk is a pretty complex function, whose workflow will be determined by a byte located at the offset 0x4 of the address specified in the first parameter.
As already stated before, we can actually control the three parameters passed at the GdiPrinterThunk function by crafting a specific LPC message.
In other words, this implies that we are able to control the GdiPrinterThunk workflow!



This function is where the actual arbitrary dereference bug lies: if the byte located at the offset 0x4 of the address passed as the first parameter will be 0x76 (0x75 on Windows 7), the memcpy function will be called with parameters completely controlled by the attacker!

<div align='center'><img src="/images/gdiprinterthunk.png" height="300" width="300" > </div> <br>


Let's take a better look at the pseudo C code:

{% highlight c %}
void GdiPrinterThunk(LPVOID firstAddress, LPVOID secondAddress, LPVOID thirdAddress)
{
  ...

    if(*((BYTE*)(firstAddress + 0x4)) == 0x75){
      ULONG64 memcpyDestinationAddress = *((ULONG64*)(firstAddress + 0x20));

      if(memcpyDestinationAddress != NULL){
        ULONG64 sourceAddress = *((ULONG64*)(firstAddress + 0x18));
        DWORD copySize = *((DWORD*)(firstAddress + 0x28));

        memcpy(memcpyDestinationAddress,sourceAddress,copySize);
      }
    }

...
}
{% endhighlight %}

This is an arbitrary pointer dereference which allows us to deliberately write to the splwow64.exe address space from a Low integrity process!


But how can we actually trigger it?

As stated before, the GdiPrinterThunk function will be called with the following parameters:

- RCX set as a the address specified in the offset 0x30 of the LPC message
- RDX set as a the address specified in the offset 0x40 of the LPC message
- R8 set as a the address specified in the offset 0x38 of the LPC message

To construct our Write What Where primitive, we can create a Shared Section and specify the address of this shared section at the offset 0x30 of the LPC message.

Once we have created the Shared section, we can set up the address we want to write to and the address we want to read from at the needed offsets and just send the LPC message!

When parsing the LPC message, the GdiPrinterThunk will access the Shared memory address specified at offset 0x30 of the message and, if the fourth byte starting from the beginning of the shared memory address function will be 0x76 (or 0x75 on Windows 7), will call the memcpy function with attacker-controlled parameters specified in the shared memory address!

# Exploiting the bug

So here we are! We can build a very powerful Write What Where Primitive!

Unfortunately, we will still need to solve some problems to actually escape the Internet Explorer Sandbox:

- <b>W^X Memory</b>: The memory of executable pages is not writable. In other words, we can’t just write a payload to an executable memory page.
- <b>ASLR</b>: We have the capability to write what we want, where we want. The problem is that we don’t have an information leak which would allow us to know the addresses of a function pointer in the target process to gain code execution by overwriting it.
- <b> Arbitrary execution</b>: We can arbitrarily write in the memory of the splwow64 process but we still don’t know how to trigger our payload whenever we want.


#### W^X Memory

Since we are not able to write to an executable memory page nor we are able to make the memory page writable by calling VirtualProtect, we will need to think about something else.
The first thing that comes to mind is to overwrite an existing function pointer with the address of a function like LoadLibraryA or WinExec and, as long as we are able to trigger a call to this function  pointer with arbitrary parameters, we would be done!

Let’s take a look at the OpenPrinterW function:

<div align='center'><img src="/images/open_printer.png" height="100" width="700" > </div> <br>

As you can see in the screenshot above, the function will move into the RAX register an address located in the .data section of the winspool.drv function and verify this address by calling LdrpValidateUserCallTarget (Control Flow Guard).

On Windows 7, it will just jump to the address saved in the .data section as you can see in the picture below.


<div align='center'><img src="/images/openprinterclean7.png" height="50" width="700" > </div> <br>
Since the .data section of the winspool.drv DLL is writable, we can just overwrite the stored address by using our Write What Where primitive!

<div align='center'><img src="/images/openprintersystem7.png" height="50" width="700" > </div>
<br>
As you can see in the picture above, the address has been overwritten with an address of our choice!


#### ASLR

To be able to achieve what described above, we will need to know the address of the winspool.drv .data section in the splwow64 process!
Luckily for us, the Address Space Layout Randomization on Windows systems is boot based: in other words, the base address of each system DLL is the same in every process until the next system reboot, regardless of their integrity level.

This implies that it will be enough to load the winspool.drv DLL in the sandboxed process address space , look for its data section and from there find the pointer to the OpenPrinter2W function and use the obtained address to overwrite it in the remote process by calling our WWW primitive.

Despite what stated above, to achieve full coverage this is not enough: on Windows 7 systems the Internet Explorer renderer process is 32-bit, while the splwow64 process is a 64 bit process. In other words, we will not be able to get the 64 bit addresses we need to successfully exploit this vulnerability.

To solve this problem, we have two options:

- Spawn a 64 bit process to leak the needed addresses.
- Use the Heaven’s gate technique to load 64 bit DLLs in our Internet Explorer Wow64 process and leak the addresses.

##### Spawning a 64 bit process
This is the simplest and most stable approach to solve the problem. Since Internet Explorer allows to write to the LocalLow folder from a Low Integrity renderer process, to leak the needed address we will just need the following:

- Create a LeakAddresses.exe 64 bit executable which will load the winspool.drv DLL, get the needed addresses and save the result in a file in the LocalLow folder.
- Drop the LeakAddresses  executable in the LocalLow folder and run it by calling the CreateProcess function. The execution will be invisible to the user since no elevation of privilege occurs: the file will be executed as a Low Integrity process.
- Obtain the needed addresses by reading the file created by our LeakAddresses executable.
- Use the obtained addresses to craft the LPC message to achieve the Write What Where primitive.

##### Using the Heaven's Gate technique

A full description of how this technique actually works is beyond the scope of this article. I remand you to this excellent article about this topic.
In a nutshell, the Heaven’s Gate is a technique which exploits how Windows actually achieves 32 bit code emulation on 64-bit systems in order to load 64 bit DLLs.

By using this technique, you will be able to load 64 bit DLLs in the address space of the Internet Explorer process and thus leaking the needed addresses without the need to write any file on disk.


#### Arbitrary execution

There is actually a reason why I chose to overwrite the pointer to the OpenPrinter2W function in the OpenPrinterW function.  
After some time spent reversing the GdiPrinterThunk function, I noticed that if we set the byte parameter to 0x6A (0x69 on Windows 7), a call to the OpenPrinterW function is issued with the first parameter being controllable by us: since the pointer to the <i> OpenPrinter2W </i> has been overwritten by us, a call to a function of our choice will be issued instead of the original one!

Unfortunately, we are able to control only the first parameter and for this reason you should choose a function which takes only one parameter.
My choice fell on two functions:

- <b>LoadLibraryA</b>: This function will load a library in the address space of the process it is called from. Since this function takes only one parameter, we could just drop a DLL in the Local Low folder and trigger a call to LoadLibraryA in the splwow64.exe process. In this way our DLL will be loaded by a Medium Integrity Level process, thus escaping the Internet Explorer sandbox.

- <b> system </b>: Since the WinExec function takes two parameters and we can control just one, we could just call this function since the msvcrt.dll DLL is loaded in the splwow64 address space (and even if it wasn’t, we could still load it by calling LoadLibraryA as stated before :D). The system function will take just one parameter and execute it as a command line as a Medium Integrity process. An attacker could, for example, run Powershell commands as a Medium Integrity user.


## Conclusions

Despite its simplicity, this bug allows an attacker to fully escape the Internet Explorer Sandbox in an extremely simple and deterministic way!
I find these types of bugs in legacy Windows components very fascinating and I think more of these kind of bugs will be found in the future.


According to my tests, this bug seems to be still working against a full-patched Windows 7 system and for this reason I chose not to publish the exploit code.
