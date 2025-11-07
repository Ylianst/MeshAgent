/*
Copyright 2021 Intel Corporation
@author Bryan Roe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

const CUSTOM_HANDLER = 0x80000000;
const GM = require('_GenericMarshal');
const CLSID_TaskScheduler = '{0f87369f-a4e5-4cfc-bd3e-73e6154572dd}';
const IID_TimeTrigger = '{b45747e0-eba7-4276-9f29-85c5bb300006}';
const IID_ExecAction = '{4c3d624d-fd6b-49a3-b9b7-09cb3cd3f047}';

const VT_EMPTY = 0;
const VT_NULL = 1;
const VT_SAFEARRAY	= 27;
const VT_BSTR	= 8;
const VT_ARRAY	= 0x2000;

const TASK_LOGON_NONE	= 0;
const TASK_LOGON_PASSWORD	= 1;
const TASK_LOGON_S4U	= 2;
const TASK_LOGON_INTERACTIVE_TOKEN	= 3;
const TASK_LOGON_GROUP	= 4;
const TASK_LOGON_SERVICE_ACCOUNT	= 5;
const TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD	= 6;


const TASK_TRIGGER_EVENT	= 0;
const TASK_TRIGGER_TIME	= 1;
const TASK_TRIGGER_DAILY	= 2;
const TASK_TRIGGER_WEEKLY	= 3;
const TASK_TRIGGER_MONTHLY	= 4;
const TASK_TRIGGER_MONTHLYDOW	= 5;
const TASK_TRIGGER_IDLE	= 6;
const TASK_TRIGGER_REGISTRATION	= 7;
const TASK_TRIGGER_BOOT	= 8;
const TASK_TRIGGER_LOGON	= 9;
const TASK_TRIGGER_SESSION_STATE_CHANGE	= 11;
const TASK_TRIGGER_CUSTOM_TRIGGER_01	= 12;

const TASK_ACTION_EXEC	= 0;
const TASK_ACTION_COM_HANDLER	= 5;
const TASK_ACTION_SEND_EMAIL	= 6;
const TASK_ACTION_SHOW_MESSAGE = 7;

const TASK_VALIDATE_ONLY = 0x1;
const TASK_CREATE = 0x2;
const TASK_UPDATE = 0x4;
const TASK_CREATE_OR_UPDATE = (TASK_CREATE | TASK_UPDATE);
const TASK_DISABLE = 0x8;
const TASK_DONT_ADD_PRINCIPAL_ACE = 0x10;
const TASK_IGNORE_REGISTRATION_TRIGGERS = 0x20;

var OleAut32 = GM.CreateNativeProxy('OleAut32.dll');
OleAut32.CreateMethod('SafeArrayAccessData');           // https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-safearrayaccessdata
OleAut32.CreateMethod('SafeArrayCreate');               // https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-safearraycreate
OleAut32.CreateMethod('SafeArrayCreateVector');         // https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-safearraycreatevector
OleAut32.CreateMethod('SafeArrayPutElement');           // https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-safearrayputelement
OleAut32.CreateMethod('SafeArrayDestroy');              // https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-safearraydestroy
OleAut32.CreateMethod('VariantClear');                  // https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-variantclear
OleAut32.CreateMethod('VariantInit');                   // https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-variantinit
OleAut32.CreateMethod('SysAllocString');                // https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-sysallocstring


// 
// This function converts an array of strings, to a variant array of BSTR
//
function ConvertStringArray(strarr)
{
    if (!strarr || !Array.isArray(strarr)) { return (GM.CreateVariable(24)); }

    var i, tmp;
    var v = GM.CreateVariable(24);
    v._tmp = [];
    var ix = GM.CreateVariable(4);
    console.info1('strarr.length=' + strarr.length);

    var safe = OleAut32.SafeArrayCreateVector(VT_BSTR, 0, strarr.length);
    if(safe.Val == 0)
    {
        throw('Error creating SafeArray');
    }

    for(i=0;i<strarr.length;++i)
    {
        ix.toBuffer().writeUInt32LE(i);
        tmp = GM.CreateVariable(strarr[i], { wide: true });
        v._tmp.push(tmp);
        var ss = OleAut32.SysAllocString(tmp);
        console.info1('SafeArrayPutElement: ' + OleAut32.SafeArrayPutElement(safe, ix, ss).Val);
    }

    OleAut32.VariantClear(v);
    v.toBuffer().writeUInt16LE(VT_ARRAY | VT_BSTR);
    safe.pointerBuffer().copy(v.toBuffer(), 8);
    //v._debug();
    return (v);
}

const UnknownFunctions =
    [
        'QueryInterface',
        'AddRef',
        'Release'
    ];

//
// Reference for ITaskService interface can be found at:
// https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nn-taskschd-itaskservice
//
const TaskServiceFunctions =
    [
        'QueryInterface',
        'AddRef',
        'Release',
        'GetTypeInfoCount',
        'GetTypeInfo',
        'GetIDsOfNames',
        'Invoke',
        'GetFolder',
        'GetRunningTasks',
        'NewTask',
        'Connect',
        'get_Connected',
        'get_TargetServer',
        'get_ConnectedUser',
        'get_ConnectedDomain',
        'get_HighestVersion'
    ];

//
// Reference for ITaskFolder interface can be found at:
// https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nn-taskschd-itaskfolder
//
const TaskFolderFunctions =
    [
        'QueryInterface',
        'AddRef',
        'Release',
        'GetTypeInfoCount',
        'GetTypeInfo',
        'GetIDsOfNames',
        'Invoke',
        'get_Name',
        'get_Path',
        'GetFolder',
        'GetFolders',
        'CreateFolder',
        'DeleteFolder',
        'GetTask',
        'GetTasks',
        'DeleteTask',
        'RegisterTask',
        'RegisterTaskDefinition',
        'GetSecurityDescriptor',
        'SetSecurityDescriptor'
    ];

//
// Reference for IRegistrationInfo interface can be found at:
// https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nn-taskschd-iregistrationinfo
//
const RegistrationInfoFunctions =
    [
        'QueryInterface',
        'AddRef',
        'Release',
        'GetTypeInfoCount',
        'GetTypeInfo',
        'GetIDsOfNames',
        'Invoke',
        'get_Description',
        'put_Description',
        'get_Author',
        'put_Author',
        'get_Version',
        'put_Version',
        'get_Date',
        'put_Date',
        'get_Documentation',
        'put_Documentation',
        'get_XmlText',
        'put_XmlText',
        'get_URI',
        'put_URI',
        'get_SecurityDescriptor',
        'put_SecurityDescriptor',
        'get_Source',
        'put_Source'
    ];

//
// Reference for ITaskDefinition interface can be found at:
// https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nn-taskschd-itaskdefinition
//
const TaskDefinitionFunctions =
    [
        'QueryInterface',
        'AddRef',
        'Release',
        'GetTypeInfoCount',
        'GetTypeInfo',
        'GetIDsOfNames',
        'Invoke',
        'get_RegistrationInfo',
        'put_RegistrationInfo',
        'get_Triggers',
        'put_Triggers',
        'get_Settings',
        'put_Settings',
        'get_Data',
        'put_Data',
        'get_Principal',
        'put_Principal',
        'get_Actions',
        'put_Actions',
        'get_XmlText',
        'put_XmlText'
    ];

//
// Reference for IPrincipal interface can be found at:
// https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nn-taskschd-iprincipal
//
const PrincipalFunctions =
    [
        'QueryInterface',
        'AddRef',
        'Release',
        'GetTypeInfoCount',
        'GetTypeInfo',
        'GetIDsOfNames',
        'Invoke',
        'get_Id',
        'put_Id',
        'get_DisplayName',
        'put_DisplayName',
        'get_UserId',
        'put_UserId',
        'get_LogonType',
        'put_LogonType',
        'get_GroupId',
        'put_GroupId',
        'get_RunLevel',
        'put_RunLevel'
    ];

//
// Reference for ITaskSettings interface can be found at:
// https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nn-taskschd-itasksettings
//
const TaskSettingsFunctions =
    [
        'QueryInterface',
        'AddRef',
        'Release',
        'GetTypeInfoCount',
        'GetTypeInfo',
        'GetIDsOfNames',
        'Invoke',
        'get_AllowDemandStart',
        'put_AllowDemandStart',
        'get_RestartInterval',
        'put_RestartInterval',
        'get_RestartCount',
        'put_RestartCount',
        'get_MultipleInstances',
        'put_MultipleInstances',
        'get_StopIfGoingOnBatteries',
        'put_StopIfGoingOnBatteries',
        'get_DisallowStartIfOnBatteries',
        'put_DisallowStartIfOnBatteries',
        'get_AllowHardTerminate',
        'put_AllowHardTerminate',
        'get_StartWhenAvailable',
        'put_StartWhenAvailable',
        'get_XmlText',
        'put_XmlText',
        'get_RunOnlyIfNetworkAvailable',
        'put_RunOnlyIfNetworkAvailable',
        'get_ExecutionTimeLimit',
        'put_ExecutionTimeLimit',
        'get_Enabled',
        'put_Enabled',
        'get_DeleteExpiredTaskAfter',
        'put_DeleteExpiredTaskAfter',
        'get_Priority',
        'put_Priority',
        'get_Compatibility',
        'put_Compatibility',
        'get_Hidden',
        'put_Hidden',
        'get_IdleSettings',
        'put_IdleSettings',
        'get_RunOnlyIfIdle',
        'put_RunOnlyIfIdle',
        'get_WakeToRun',
        'put_WakeToRun',
        'get_NetworkSettings',
        'put_NetworkSettings'
    ];

//
// Reference for IIdleSettings interface can be found at:
// https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nn-taskschd-iidlesettings
//
const IdleSettingsFunctions =
    [
        'QueryInterface',
        'AddRef',
        'Release',
        'GetTypeInfoCount',
        'GetTypeInfo',
        'GetIDsOfNames',
        'Invoke',
        'get_IdleDuration',
        'put_IdleDuration',
        'get_WaitTimeout',
        'put_WaitTimeout',
        'get_StopOnIdleEnd',
        'put_StopOnIdleEnd',
        'get_RestartOnIdle',
        'put_RestartOnIdle'
    ];

//
// Reference for ITriggerCollection interface can be found at:
// https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nn-taskschd-itriggercollection
//
const TriggerCollectionFunctions =
    [
        'QueryInterface',
        'AddRef',
        'Release',
        'GetTypeInfoCount',
        'GetTypeInfo',
        'GetIDsOfNames',
        'Invoke',
        'get_Count',
        'get_Item',
        'get__NewEnum',
        'Create',
        'Remove',
        'Clear'
    ];

//
// Reference for ITrigger interface can be found at:
// https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nn-taskschd-itrigger
//
const TriggerFunctions =
    [
        'QueryInterface',
        'AddRef',
        'Release',
        'GetTypeInfoCount',
        'GetTypeInfo',
        'GetIDsOfNames',
        'Invoke',
        'get_Type',
        'get_Id',
        'put_Id',
        'get_Repetition',
        'put_Repetition',
        'get_ExecutionTimeLimit',
        'put_ExecutionTimeLimit',
        'get_StartBoundary',
        'put_StartBoundary',
        'get_EndBoundary',
        'put_EndBoundary',
        'get_Enabled',
        'put_Enabled'
    ];

//
// Reference for ITimeTrigger interface can be found at:
// https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nn-taskschd-itimetrigger
//
const TimeTriggerFunctions =
    [
        'QueryInterface',
        'AddRef',
        'Release',
        'GetTypeInfoCount',
        'GetTypeInfo',
        'GetIDsOfNames',
        'Invoke',
        'get_Type',
        'get_Id',
        'put_Id',
        'get_Repetition',
        'put_Repetition',
        'get_ExecutionTimeLimit',
        'put_ExecutionTimeLimit',
        'get_StartBoundary',
        'put_StartBoundary',
        'get_EndBoundary',
        'put_EndBoundary',
        'get_Enabled',
        'put_Enabled',
        'get_RandomDelay',
        'put_RandomDelay'
    ];

//
// Reference for IActionCollection interface can be found at:
// https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nn-taskschd-iactioncollection
//
const ActionCollectionFunctions =
    [
        'QueryInterface',
        'AddRef',
        'Release',
        'GetTypeInfoCount',
        'GetTypeInfo',
        'GetIDsOfNames',
        'Invoke',
        'get_Count',
        'get_Item',
        'get__NewEnum',
        'get_XmlText',
        'put_XmlText',
        'Create',
        'Remove',
        'Clear',
        'get_Context',
        'put_Context'
    ];

// 
// Reference for IAction interface can be found at:
// https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nn-taskschd-iaction
//
const ActionFunctions =
    [
        'QueryInterface',
        'AddRef',
        'Release',
        'GetTypeInfoCount',
        'GetTypeInfo',
        'GetIDsOfNames',
        'Invoke',
        'get_Id',
        'put_Id',
        'get_Type' 
    ];

//
// Reference for IExecAction interface can be found at:
// https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nn-taskschd-iexecaction
//
const ExecActionFunctions =
    [
        'QueryInterface',
        'AddRef',
        'Release',
        'GetTypeInfoCount',
        'GetTypeInfo',
        'GetIDsOfNames',
        'Invoke',
        'get_Id',
        'put_Id',
        'get_Type',
        'get_Path',
        'put_Path',
        'get_Arguments',
        'put_Arguments',
        'get_WorkingDirectory',
        'put_WorkingDirectory'
    ];

//
// Reference for IRegisteredTask interface can be found at:
// https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nn-taskschd-iregisteredtask
//
const RegisteredTaskFunctions =
    [
        'QueryInterface',
        'AddRef',
        'Release',
        'GetTypeInfoCount',
        'GetTypeInfo',
        'GetIDsOfNames',
        'Invoke',
        'get_Name',
        'get_Path',
        'get_State',
        'get_Enabled',
        'put_Enabled',
        'Run',
        'RunEx',
        'GetInstances',
        'get_LastRunTime',
        'get_LastTaskResult',
        'get_NumberOfMissedRuns',
        'get_NextRunTime',
        'get_Definition',
        'get_Xml',
        'GetSecurityDescriptor',
        'SetSecurityDescriptor',
        'Stop',
        'GetRunTimes'
    ];

//
// JavaScript abstraction for Task. This constructor adds the "Run" function, and 
// adds a finalizer to handle cleanup and unregistration
//
function taskObject(j)
{
    this._task = j;
    this.run = function run(arr)
    {
        var val = ConvertStringArray(arr);
        var running = GM.CreatePointer();
        this._task.funcs.Run(this._task.Deref(), val, running);
    };
    require('events').EventEmitter.call(this);
    this.once('~', function ()
    {
        this._task._rf.funcs.Release(this._task._rf.Deref());
        this._task._ts.funcs.Release(this._task._ts);

        this._task._rf = null;
        this._task._ts = null;
        this._task = null;
        console.info1('taskObject Finalized');
    })
}

//
// Finds and returns the specified Task
//
function getTask(options)
{
    var hr;
    var serverName = GM.CreateVariable(24);
    var user = GM.CreateVariable(24);
    var domain = GM.CreateVariable(24);
    var password = GM.CreateVariable(24);
    var rootFolder = GM.CreatePointer();
    var task = GM.CreatePointer();

    // Connect to the TaskScheduler COM object
    var taskService = require('win-com').createInstance(require('win-com').CLSIDFromString(CLSID_TaskScheduler), require('win-com').IID_IUnknown);
    taskService.funcs = require('win-com').marshalFunctions(taskService, TaskServiceFunctions);

    taskService.funcs.Connect._callType = 1;
    hr = taskService.funcs.Connect(taskService, serverName, user, domain, password);
    if (hr.Val != 0)
    {
        taskService.funcs.Release(taskService);
        throw ('ITaskService::Connect failed ' + hr.Val);
    }

    // Get the folder object
    hr = taskService.funcs.GetFolder(taskService, GM.CreateVariable('\\', { wide: true }), rootFolder);
    if (hr.Val != 0)
    {
        taskService.funcs.Release(taskService);
        throw ('ITaskService failed to get Root folder ' + hr.Val);
    }
    rootFolder.funcs = require('win-com').marshalFunctions(rootFolder.Deref(), TaskFolderFunctions);

    // Get the tasks for that folder object
    hr = rootFolder.funcs.GetTask(rootFolder.Deref(), GM.CreateVariable(options.name, { wide: true }), task);
    if (hr.Val != 0)
    {
        rootFolder.funcs.Release(rootFolder.Deref());
        taskService.funcs.Release(taskService);
        throw ('Failed to get Task: ' + options.name + ' [' + hr.Val + ']');
    }
    task.funcs = require('win-com').marshalFunctions(task.Deref(), RegisteredTaskFunctions);
    task.funcs.Run._callType = CUSTOM_HANDLER | 2; // This must be declared like this, so that VARIANT can be marshaled correctly
    task._rf = rootFolder;
    task._ts = taskService;

    return (new taskObject(task));
}

// 
// Delete a scheduled task
//
function deleteTask(options)
{
    if (typeof (options) == 'string') { options = { name: options } }
    var hr;
    var serverName = GM.CreateVariable(24);
    var user = GM.CreateVariable(24);
    var domain = GM.CreateVariable(24);
    var password = GM.CreateVariable(24);
    var rootFolder = GM.CreatePointer();

    // Instantiate and connect to the Window Task Scheduler service
    var taskService = require('win-com').createInstance(require('win-com').CLSIDFromString(CLSID_TaskScheduler), require('win-com').IID_IUnknown);
    taskService.funcs = require('win-com').marshalFunctions(taskService, TaskServiceFunctions);
    hr = taskService.funcs.Connect._callType = 1;
    hr = taskService.funcs.Connect(taskService, serverName, user, domain, password);
    if (hr.Val != 0)
    {
        taskService.funcs.Release(taskService);
        throw ('ITaskService::Connect failed ' + hr.Val);
    }

    // Get the root folder
    hr = taskService.funcs.GetFolder(taskService, GM.CreateVariable('\\', { wide: true }), rootFolder);
    if (hr.Val != 0)
    {
        taskService.funcs.Release(taskService);
        throw ('ITaskService failed to get Root folder ' + hr.Val);
    }
    console.info1('Deleting Task: ' + options.name);
    rootFolder.funcs = require('win-com').marshalFunctions(rootFolder.Deref(), TaskFolderFunctions);

    // Delete the specified task
    hr = rootFolder.funcs.DeleteTask(rootFolder.Deref(), GM.CreateVariable(options.name, { wide: true }), 0);
    if (hr.Val != 0)
    {
        rootFolder.funcs.Release(rootFolder.Deref());
        taskService.funcs.Release(taskService);
        throw ('Could not delete Task: ' + options.name);
    }
    rootFolder.funcs.Release(rootFolder.Deref());
    taskService.funcs.Release(taskService);
}

//
// Add a new task to the Windows Task Scheduler
//
function addTask(options)
{
    // Set some defaults if they are not specified
    if (!options) { throw ('Need to specify options object'); }
    if (!options.author) { options.author = 'win-task'; }
    if (!options.id) { options.id = 'win-task'; }
    if (!options.startTime) { options.startTime = '2021-01-01T00:00'; }
    if (!options.endTime) { options.endTime = '2021-01-01T00:30'; }


    // Instantiate the Windows Task Scheduler service
    var taskService = require('win-com').createInstance(require('win-com').CLSIDFromString(CLSID_TaskScheduler), require('win-com').IID_IUnknown);
    taskService.funcs = require('win-com').marshalFunctions(taskService, TaskServiceFunctions);

    var hr;
    var serverName = GM.CreateVariable(24);
    var user = GM.CreateVariable(24);
    var domain = GM.CreateVariable(24);
    var password = GM.CreateVariable(24);

    var rootFolder = GM.CreatePointer();
    var task = GM.CreatePointer();
    var regInfo = GM.CreatePointer();
    var principal = GM.CreatePointer();
    var taskSettings = GM.CreatePointer();
    var triggerCollection = GM.CreatePointer();
    var unknownTrigger = GM.CreatePointer();
    var timeTrigger = GM.CreatePointer();
    var actionCollection = GM.CreatePointer();
    var taskAction = GM.CreatePointer();
    var execAction = GM.CreatePointer();
    var registeredTask = GM.CreatePointer();

    // Connect to the Task Scheduler
    taskService.funcs.Connect._callType = 1;
    hr = taskService.funcs.Connect(taskService, serverName, user, domain, password);
    if (hr.Val != 0)
    {
        taskService.funcs.Release(taskService);
        throw ('ITaskService::Connect failed ' + hr.Val);
    }
    hr = taskService.funcs.GetFolder(taskService, GM.CreateVariable('\\', { wide: true }), rootFolder);
    if (hr.Val != 0)
    {
        taskService.funcs.Release(taskService);
        throw ('ITaskService failed to get Root folder ' + hr.Val);
    }
    rootFolder.funcs = require('win-com').marshalFunctions(rootFolder.Deref(), TaskFolderFunctions);

    // Create an empty task
    hr = taskService.funcs.NewTask(taskService, 0, task);
    taskService.funcs.Release(taskService); // No longer needed going forward
    if (hr.Val != 0)
    {
        rootFolder.funcs.Release(rootFolder.Deref());
        throw ('ITaskService failed to create new task ' + hr.Val);
    }

    // Fetch the registration data for the ampty task
    task.funcs = require('win-com').marshalFunctions(task.Deref(), TaskDefinitionFunctions);
    hr = task.funcs.get_RegistrationInfo(task.Deref(), regInfo);
    if (hr.Val != 0)
    {
        rootFolder.funcs.Release(rootFolder.Deref());
        task.funcs.Release(task.Deref());
        throw ('ITaskService failed to get RegistrationInfo ' + hr.Val);
    }

    regInfo.funcs = require('win-com').marshalFunctions(regInfo.Deref(), RegistrationInfoFunctions);
    regInfo.funcs.Release(regInfo.Deref()); // Not needed going forward
    hr = regInfo.funcs.put_Author(regInfo.Deref(), GM.CreateVariable(options.author, {wide: true}));    
    if (hr.Val != 0)
    {
        rootFolder.funcs.Release(rootFolder.Deref());
        task.funcs.Release(task.Deref());
        throw ('ITaskService failed to put Author ' + hr.Val);
    }

    if (options.userID != null || options.user)
    {
        if (options.user == 'SYSTEM') { options.userID = 'S-1-5-18'; } // If the task is to run as SYSTEM, set the security descriptor for SYSTEM
        hr = task.funcs.get_Principal(task.Deref(), principal);
        if (hr.Val != 0)
        {
            rootFolder.funcs.Release(rootFolder.Deref());
            task.funcs.Release(task.Deref());
            throw ('ITaskService failed to get Principal ' + hr.Val);
        }

        principal.funcs = require('win-com').marshalFunctions(principal.Deref(), PrincipalFunctions);
        if (!options.userID && options.user && options.user != 'SYSTEM')
        {
            try
            {
                // If the task is to run as user, we need to fetch the Windows Security Descriptor for that user
                options.userID = require('win-registry').usernameToUserKey({ user: options.user, domain: options.domain });
            }
            catch (z)
            {
                principal.funcs.Release(principal.Deref()); // No longer needed
                rootFolder.funcs.Release(rootFolder.Deref());
                task.funcs.Release(task.Deref());
                throw ('ITaskService failed to resolve username: ' + options.user + ' ' + hr.Val);
            }
        }
        
        hr = principal.funcs.put_LogonType(principal.Deref(), (options.user == 'SYSTEM' ? TASK_LOGON_SERVICE_ACCOUNT : TASK_LOGON_INTERACTIVE_TOKEN));
        if (hr.Val != 0)
        {
            principal.funcs.Release(principal.Deref()); // No longer needed
            rootFolder.funcs.Release(rootFolder.Deref());
            task.funcs.Release(task.Deref());
            throw ('ITaskService failed to put logonType ' + hr.Val);
        }

        if (options.userID)
        {
            // Set the security descriptor for the task
            hr = principal.funcs.put_UserId(principal.Deref(), GM.CreateVariable(options.userID, { wide: true }));
            if (hr.Val != 0)
            {
                principal.funcs.Release(principal.Deref()); // No longer needed
                rootFolder.funcs.Release(rootFolder.Deref());
                task.funcs.Release(task.Deref());
                throw ('ITaskService failed to put user id ' + hr.Val);
            }
        }
        principal.funcs.Release(principal.Deref()); // No longer needed
    }

    hr = task.funcs.get_Settings(task.Deref(), taskSettings);
    if (hr.Val != 0)
    {
        rootFolder.funcs.Release(rootFolder.Deref());
        task.funcs.Release(task.Deref());
        throw ('ITaskService failed to get settings ' + hr.Val);
    }
    taskSettings.funcs = require('win-com').marshalFunctions(taskSettings.Deref(), TaskSettingsFunctions);

    // Set some atrtibutes, so that the task will run, regardless of AC power state and network state
    if(taskSettings.funcs.put_StopIfGoingOnBatteries(taskSettings.Deref(), 0).Val != 0 || 
        taskSettings.funcs.put_DisallowStartIfOnBatteries(taskSettings.Deref(), 0).Val != 0 ||
        taskSettings.funcs.put_RunOnlyIfNetworkAvailable(taskSettings.Deref(), 0).Val != 0)
    {
        rootFolder.funcs.Release(rootFolder.Deref());
        task.funcs.Release(task.Deref());
        throw ('ITaskService failed to set attributes ' + hr.Val);
    }

    hr = task.funcs.get_Triggers(task.Deref(), triggerCollection);
    if (hr.Val != 0)
    {
        rootFolder.funcs.Release(rootFolder.Deref());
        task.funcs.Release(task.Deref());
        throw ('ITaskService failed to get Triggers ' + hr.Val);
    }
    triggerCollection.funcs = require('win-com').marshalFunctions(triggerCollection.Deref(), TriggerCollectionFunctions);

    // Create the trigger
    hr = triggerCollection.funcs.Create(triggerCollection.Deref(), TASK_TRIGGER_TIME, unknownTrigger);
    if (hr.Val != 0)
    {
        rootFolder.funcs.Release(rootFolder.Deref());
        task.funcs.Release(task.Deref());
        throw ('ITaskService failed to get create trigger ' + hr.Val);
    }
    unknownTrigger.funcs = require('win-com').marshalFunctions(unknownTrigger.Deref(), UnknownFunctions);

    hr = unknownTrigger.funcs.QueryInterface(unknownTrigger.Deref(), require('win-com').IIDFromString(IID_TimeTrigger), timeTrigger);
    if (hr.Val != 0)
    {
        rootFolder.funcs.Release(rootFolder.Deref());
        task.funcs.Release(task.Deref());
        throw ('QueryInterface failed for IID_TimeTrigger ' + hr.Val);
    }
    timeTrigger.funcs = require('win-com').marshalFunctions(unknownTrigger.Deref(), TimeTriggerFunctions);

    hr = timeTrigger.funcs.put_Id(timeTrigger.Deref(), GM.CreateVariable(options.id, { wide: true }));
    if (hr.Val != 0)
    {
        rootFolder.funcs.Release(rootFolder.Deref());
        task.funcs.Release(task.Deref());
        throw ('ITaskService failed to get put TriggerID ' + hr.Val);
    }

    // Set the start time
    hr = timeTrigger.funcs.put_StartBoundary(timeTrigger.Deref(), GM.CreateVariable(options.startTime, { wide: true }));
    if (hr.Val != 0)
    {
        rootFolder.funcs.Release(rootFolder.Deref());
        task.funcs.Release(task.Deref());
        throw ('ITaskService failed to set StartBoundary ' + hr.Val);
    }

    // Set the end time, if specified
    if (options.endTime)
    {
        hr = timeTrigger.funcs.put_EndBoundary(timeTrigger.Deref(), GM.CreateVariable(options.endTime, { wide: true }));
        if(hr.Val!=0)
        {
            rootFolder.funcs.Release(rootFolder.Deref());
            task.funcs.Release(task.Deref());
            throw ('ITaskService failed to set EndBoundary ' + hr.Val);
        }
    }

    // Fetch the ActionCollection
    hr = task.funcs.get_Actions(task.Deref(), actionCollection);
    if (hr.Val != 0)
    {
        rootFolder.funcs.Release(rootFolder.Deref());
        task.funcs.Release(task.Deref());
        throw ('ITaskService failed to get Actions ' + hr.Val);
    }
    actionCollection.funcs = require('win-com').marshalFunctions(actionCollection.Deref(), ActionCollectionFunctions);

    // Now we're going to create an ExecAction
    hr = actionCollection.funcs.Create(actionCollection.Deref(), TASK_ACTION_EXEC, taskAction);
    if (hr.Val != 0)
    {
        rootFolder.funcs.Release(rootFolder.Deref());
        task.funcs.Release(task.Deref());
        throw ('ITaskService failed to create Task ' + hr.Val);
    }
    taskAction.funcs = require('win-com').marshalFunctions(taskAction.Deref(), ActionFunctions);

    hr = taskAction.funcs.QueryInterface(taskAction.Deref(), require('win-com').IIDFromString(IID_ExecAction), execAction);
    if (hr.Val != 0)
    {
        rootFolder.funcs.Release(rootFolder.Deref());
        task.funcs.Release(task.Deref());
        throw ('QueryInterface failed for IID_ExecAction ' + hr.Val);
    }
    execAction.funcs = require('win-com').marshalFunctions(execAction.Deref(), ExecActionFunctions);

    hr = execAction.funcs.put_Path(execAction.Deref(), GM.CreateVariable(options.execPath, { wide: true }));
    if (hr.Val != 0)
    {
        rootFolder.funcs.Release(rootFolder.Deref());
        task.funcs.Release(task.Deref());
        throw ('ITaskService failed to put action path ' + hr.Val);
    }

    // Set the exec arguments if specified
    if (options.arguments && Array.isArray(options.arguments))
    {
        hr = execAction.funcs.put_Arguments(execAction.Deref(), GM.CreateVariable(options.arguments.join(' '), { wide: true }));
        if (hr.Val != 0)
        {
            rootFolder.funcs.Release(rootFolder.Deref());
            task.funcs.Release(task.Deref());
            throw ('ITaskService failed to put action arguments ' + hr.Val);
        }  
    }

    // Set the working path if specified
    if (options.workingDirectory)
    {
        hr = execAction.funcs.put_WorkingDirectory(execAction.Deref(), GM.CreateVariable(options.workingDirectory, { wide: true }));
        if (hr.Val != 0)
        {
            rootFolder.funcs.Release(rootFolder.Deref());
            task.funcs.Release(task.Deref());
            throw ('ITaskService failed to put working directory ' + hr.Val);
        } 
    }

    // Register the new task
    var vvar = GM.CreateVariable(GM.PointerSize == 8 ? 24 : 16);
    rootFolder.funcs.RegisterTaskDefinition._callType = 1 | CUSTOM_HANDLER;
    hr = rootFolder.funcs.RegisterTaskDefinition(
        rootFolder.Deref(),
        GM.CreateVariable(options.name, { wide: true }),
        task.Deref(),
        TASK_CREATE_OR_UPDATE,
        vvar,
        vvar,
        TASK_LOGON_INTERACTIVE_TOKEN,
        GM.CreateVariable('', { wide: true }),
        registeredTask);

    rootFolder.funcs.Release(rootFolder.Deref());
    task.funcs.Release(task.Deref());
    if(hr.Val!=0)
    {
        throw ('ITaskService failed to register action ' + hr.Val);
    }
}

module.exports =
    {
        addTask: addTask,
        deleteTask: deleteTask,
        getTask: getTask,
        convert: ConvertStringArray
    };