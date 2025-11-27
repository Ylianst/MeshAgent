/*
Copyright 2009-2014 Intel Corporation

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

/*
This file along with WebRTC.dll contains all the classes and code needed
to use WebRTC from C#. All you need to do is include this WebRTC.cs file
in your project, add "using OpenSource.WebRTC" to your code and start
using WebRTC. Documentation at: http://opentools.homeip.net/webrtc
*/

using System;
using System.IO;
using System.Net;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;

namespace OpenSource.WebRTC
{
    public class WebRTCCommons
    {
        #region String Helpers
        private static string ReadString(IntPtr source, int length)
        {
            return (Marshal.PtrToStringAnsi(source, length));
        }
        private static string ReadString(IntPtr source)
        {
            return (Marshal.PtrToStringAnsi(source));
        }
        #endregion

        #region IPAddress Helpers

        #region P-Invoke Declarations
        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr ILibWrapper_SockAddr_GetAddressString(IntPtr addr, IntPtr buffer, int bufferLength);
        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern ushort ILibWrapper_SockAddr_GetPort(IntPtr addr);
        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr ILibWrapper_SockAddr_FromString(IntPtr buffer, ushort port);
        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr ILibWrapper_SockAddr_FromString6(IntPtr addr, ushort port);
        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern void ILibWrapper_FreeSockAddr(IntPtr addr);
        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr ILibWrapper_SockAddr_FromBytes(IntPtr buffer, int offset, int length);
        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern int ILibWrapper_SockAddrIn6_Size();
        #endregion

        public static int GetSockAddrIn6Size()
        {
            return (ILibWrapper_SockAddrIn6_Size());
        }

        /// <summary>
        /// Returns the port number specified by the native sockaddr structure, in host order.
        /// Note: Supports both IPv6 and IPv4
        /// </summary>
        /// <param name="sockaddr">The native sockaddr structure</param>
        /// <returns>Port number in host order</returns>
        public static ushort GetPort(IntPtr sockaddr)
        {
            return (ILibWrapper_SockAddr_GetPort(sockaddr));
        }
        /// <summary>
        /// Converts a native sockaddr structure to a managed IPEndPoint object.
        /// Note: Supports both IPv6 and IPv4
        /// </summary>
        /// <param name="sockaddr">The native sockaddr structure</param>
        /// <returns>An IPEndPoint object representing the sockaddr structure</returns>
        public static IPEndPoint GetIPEndPoint(IntPtr sockaddr)
        {
            return (new IPEndPoint(GetIPAddress(sockaddr), (int)GetPort(sockaddr)));
        }
        public static IPEndPoint GetIPEndPoint(byte[] buffer)
        {
            return (GetIPEndPoint(buffer, 0, buffer.Length));
        }
        public static IPEndPoint GetIPEndPoint(byte[] buffer, int offset, int length)
        {
            IntPtr native = Marshal.AllocHGlobal(length);
            Marshal.Copy(buffer, offset, native, length);

            IntPtr sockaddr = ILibWrapper_SockAddr_FromBytes(native, 0, length);
            IPEndPoint retVal = GetIPEndPoint(sockaddr);

            ILibWrapper_FreeSockAddr(sockaddr);
            return (retVal);
        }
        /// <summary>
        /// Returns the IP Address specified by the native sockaddr structure.
        /// Note: Supports both IPv6 and IPv4
        /// </summary>
        /// <param name="sockaddr">The native sockaddr structure</param>
        /// <returns>An IPAddress object representing the address specified by sockaddr</returns>
        public static IPAddress GetIPAddress(IntPtr sockaddr)
        {
            if (sockaddr != IntPtr.Zero)
            {
                IntPtr buffer = Marshal.AllocHGlobal(255);
                IntPtr str = ILibWrapper_SockAddr_GetAddressString(sockaddr, buffer, 255);
                IPAddress retVal = IPAddress.Parse(ReadString(str));
                Marshal.FreeHGlobal(buffer);
                return (retVal);
            }
            else
            {
                return (null);
            }
        }
        /// <summary>
        /// Converts a managed IPEndPoint object to a native sockaddr structure. You MUST call "FreeSockAddr" to release memory consumed by the native structure.
        /// Note: Supports both IPv6 and IPv4
        /// </summary>
        /// <param name="endPoint">The IPEndPoint to convert</param>
        /// <returns>Managed pointer to sockaddr* representing the IPEndPoint</returns>
        public static IntPtr GetSockAddr(IPEndPoint endPoint)
        {
            return (GetSockAddr(endPoint.Address, (ushort)endPoint.Port));
        }
        /// <summary>
        /// Creates a native sockaddr structure, representing the IPAddress and port specified. You MUST call "FreeSockAddr" to release the memory used by the native structure
        /// Note: Supports both IPv6 and IPv4
        /// </summary>
        /// <param name="addr">IPAddress to specify in the structure</param>
        /// <param name="port">The port number (in host order) to specify</param>
        /// <returns>Managed pointer to sockaddr* representing the IPEndPoint</returns>
        public static IntPtr GetSockAddr(IPAddress addr, ushort port)
        {
            IntPtr buffer = Marshal.StringToHGlobalAnsi(addr.ToString());
            IntPtr RetVal;

            switch (addr.AddressFamily)
            {
                case System.Net.Sockets.AddressFamily.InterNetwork:
                    RetVal = ILibWrapper_SockAddr_FromString(buffer, port);
                    break;
                case System.Net.Sockets.AddressFamily.InterNetworkV6:
                    RetVal = ILibWrapper_SockAddr_FromString6(buffer, port);
                    break;
                default:
                    RetVal = IntPtr.Zero;
                    break;
            }

            Marshal.FreeHGlobal(buffer);
            return (RetVal);
        }
        /// <summary>
        /// Releases memory that was allocated to store the native sockaddr structure created by "GetSockAddr".
        /// </summary>
        /// <param name="SockAddr">The structure to free</param>
        public static void FreeSockAddr(IntPtr SockAddr)
        {
            if (SockAddr != IntPtr.Zero)
            {
                ILibWrapper_FreeSockAddr(SockAddr);
            }
        }

        #endregion

        #region Custom Awaiter Class
        /// <summary>
        /// An awaitable Template, so that you can take advantage of await and continueWith, without relying on Tasks
        /// </summary>
        /// <typeparam name="T">The result type for GetResult and await</typeparam>
        public class CustomAwaiter<T>
        {
            private TaskCompletionSource<T> mTCS;
            private ConfiguredTaskAwaitable<T>.ConfiguredTaskAwaiter mConfigedTaskAwaiter;
            private Action<Task<T>, int> mSetStateFlags;
            private bool _captureContext;
            /// <summary>
            /// Instantiates a new reusable Awaiter
            /// </summary>
            public CustomAwaiter(bool captureContext = false)
            {             
                _captureContext = captureContext;
                mTCS = new TaskCompletionSource<T>();
                mConfigedTaskAwaiter = mTCS.Task.ConfigureAwait(captureContext).GetAwaiter();
               
                FieldInfo stateFlagsField = typeof(Task).GetField("m_stateFlags", BindingFlags.Instance | BindingFlags.NonPublic);
                ParameterExpression taskExp = Expression.Parameter(typeof(Task<T>));
                ParameterExpression intExp = Expression.Parameter(typeof(int));

                MemberExpression M = Expression.Field(taskExp, stateFlagsField);
                BinaryExpression AssignExp = Expression.Assign(M, intExp);
                mSetStateFlags = Expression.Lambda<Action<Task<T>, int>>(AssignExp, taskExp, intExp).Compile();
            }
            /// <summary>
            /// Get's the underlying awaiter object. (Note: Used by compiler)
            /// </summary>
            /// <returns>Awaiter</returns>
            public ConfiguredTaskAwaitable<T>.ConfiguredTaskAwaiter GetAwaiter()
            {
                return (mConfigedTaskAwaiter);
            }
            /// <summary>
            /// Marks the completion of an asyncronous operation.
            /// </summary>
            /// <param name="val">Completion object to pass to the awaiter</param>
            public void SetComplete(T val)
            {
                mTCS.TrySetResult(val);
            }
            /// <summary>
            /// Returns the underlying Task object
            /// </summary>
            public Task<T> Task
            {
                get
                {
                    return (mTCS.Task);
                }
            }
            /// <summary>
            /// Reset the state of the Awaiter, so it can be re-used
            /// </summary>
            public void Reset()
            {
                mTCS = new TaskCompletionSource<T>(_captureContext);
                mConfigedTaskAwaiter = mTCS.Task.ConfigureAwait(false).GetAwaiter();
            }
        }
        #endregion

        /// <summary>
        /// Managed wrapper for a Microstack Chain
        /// </summary>
        public class MicrostackChain : IDisposable
        {
           #region RemoteLogging Details
            public enum RemoteLogging_Modules
            {
	            UNKNOWN			= 0x00,			//!< UNKNOWN Module
	            WebRTC_STUN_ICE	= 0x02,			//!< WebRTC: STUN/ICE
	            WebRTC_DTLS		= 0x04,			//!< WebRTC: DTLS
	            WebRTC_SCTP		= 0x08,			//!< WebRTC: SCTP
	            Agent_GuardPost	= 0x10,			//!< Mesh Agent: Guard Post
	            Agent_P2P			= 0x20,			//!< Mesh Agent: Peer to Peer
	            Agent_KVM			= 0x200,		//!< Mesh AGent: KVM
	            Microstack_AsyncSocket	= 0x40,	//!< Microstack: AsyncSocket, AsyncServerSocket, AsyncUDPSocket
	            Microstack_Web			= 0x80,	//!< Microstack: WebServer, WebSocket, WebClient
	            Microstack_Pipe			= 0x400,//!< Microstack: Pipe
	            Microstack_Generic		= 0x100 //!< Microstack: Generic
            }
           public enum RemoteLogging_Flags
            {
	            NONE				= 0x00,	//!< NONE
	            DisableLogging		= 0x01,	//!< DISABLED
	            VerbosityLevel_1	= 0x02, //!< Verbosity Level 1
	            VerbosityLevel_2	= 0x04, //!< Verbosity Level 2
	            VerbosityLevel_3	= 0x08, //!< Verbosity Level 3
	            VerbosityLevel_4	= 0x10, //!< Verbosity Level 4
	            VerbosityLevel_5	= 0x20  //!< Verbosity Level 5
            }

           public void RemoteLog(RemoteLogging_Modules module, RemoteLogging_Flags flag, string msg)
           {
               IntPtr astr = Marshal.StringToHGlobalAnsi(msg);
               ILibWrapper_RemoteLogging_Print(mChain, module, flag, astr);
               Marshal.FreeHGlobal(astr);
           }

            #endregion


           public ushort LoggingPort
            {
                get
                {
                    return (_loggingPort);
                }
                set
                {
                    _loggingPort = ILibWrapper_StartDefaultLogger(mChain, value);
                }
            }
            private ushort _loggingPort = 0;
            public readonly IntPtr mBaseTimer;
            public readonly IntPtr mChain;
            private Thread mChainThread = null;
            private bool disposing = false;

            public delegate void StopChainHandler(MicrostackChain sender);
            public event StopChainHandler OnStopChain;

            #region Chain Management

            #region P-Invoke Declarations
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            private delegate void ILibLifeTime_OnCallback(IntPtr obj);

            [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
            private static extern IntPtr ILibWrapper_CreateMicrostackChain();
            [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
            private static extern void ILibWrapper_StartChain(IntPtr chain);
            [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
            private static extern void ILibWrapper_StopChain(IntPtr chain);
            [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
            private static extern int ILibWrapper_IsChainRunning(IntPtr chain);
            [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
            private static extern IntPtr ILibWrapper_DLL_GetBaseTimer(IntPtr chain);
            [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
            private static extern void ILibWrapper_LifeTimeAddEx(IntPtr LifetimeMonitorObject, IntPtr data, int ms, ILibLifeTime_OnCallback Callback, ILibLifeTime_OnCallback Destroy);
            [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
            private static extern void ILibWrapper_LifeTimeRemove(IntPtr LifeTimeToken, IntPtr data);
            [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
            private static extern int ILibWrapper_DLL_IsChainDisposing(IntPtr chain);
            [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
            private static extern ushort ILibWrapper_StartDefaultLogger(IntPtr chain, ushort portNumber);
            [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
            private static extern void ILibWrapper_RemoteLogging_Print(IntPtr chain, RemoteLogging_Modules module, RemoteLogging_Flags flags, IntPtr msg);
            #endregion

            #region LifeTimeMonitor
            public delegate void LifeTimeExpirationHandler(MicrostackChain sender, object data);
            private Dictionary<object, Tuple<LifeTimeExpirationHandler, LifeTimeExpirationHandler>> LifeTimeTable = new Dictionary<object, Tuple<LifeTimeExpirationHandler, LifeTimeExpirationHandler>>();
            private ILibLifeTime_OnCallback nLifetimeExpireSink, nLifetimeDestroySink;

            private void LifetimeExpireSink(IntPtr data)
            {
                object mData = Marshal.GetObjectForIUnknown(data);
                Marshal.Release(data);

                LifeTimeExpirationHandler expire;

                lock (LifeTimeTable)
                {                    
                    expire = LifeTimeTable[mData].Item1;
                    LifeTimeTable.Remove(mData);
                }

                if (expire != null) { expire(this, mData); }
            }
            private void LifetimeDestroySink(IntPtr data)
            {
                object mData = Marshal.GetObjectForIUnknown(data);
                Marshal.Release(data);

                LifeTimeExpirationHandler destroy = null;

                lock (LifeTimeTable)
                {
                    if (LifeTimeTable.ContainsKey(mData))
                    {
                        destroy = LifeTimeTable[mData].Item2;
                        LifeTimeTable.Remove(mData);
                    }
                }

                if (destroy != null) { destroy(this, mData); }
            }
            /// <summary>
            /// Add an object expiration timer, using the default Microstack Chain LifeTimeMonitor
            /// </summary>
            /// <param name="data">The object to associate the expiration</param>
            /// <param name="milliseconds">Number of milliseconds to expire the object</param>
            /// <param name="OnExpire">Triggered when the timeout has elapsed</param>
            /// <param name="OnDestroy">Triggered when the timeout has been canceled</param>
            public void AddLifeTime(object data, int milliseconds, LifeTimeExpirationHandler OnExpire, LifeTimeExpirationHandler OnDestroy)
            {
                lock (LifeTimeTable)
                {
                    LifeTimeTable.Add(data, Tuple.Create<LifeTimeExpirationHandler, LifeTimeExpirationHandler>(OnExpire, OnDestroy));
                }
                ILibWrapper_LifeTimeAddEx(mBaseTimer, Marshal.GetIUnknownForObject(data), milliseconds, nLifetimeExpireSink, nLifetimeDestroySink);
            }
            /// <summary>
            /// Removes/Cancels an object expiration timer
            /// </summary>
            /// <param name="data"></param>
            public void RemoveLifeTime(object data)
            {
                IntPtr nData = Marshal.GetIUnknownForObject(data);
                lock (LifeTimeTable)
                {
                    LifeTimeTable.Remove(data);
                }

                ILibWrapper_LifeTimeRemove(mBaseTimer, nData);
            }
            #endregion


            /// <summary>
            /// Asyncronously starts the Microstack Chain.
            /// </summary>
            public void StartChain()
            {
                mChainThread = new Thread((ThreadStart)(() =>
                    {
                        ILibWrapper_StartChain(mChain);
                    }));
                mChainThread.Start();
            }
            /// <summary>
            /// Stops the Microstack Chain
            /// </summary>
            public void StopChain()
            {
                if (OnStopChain != null)
                {
                    OnStopChain(this);
                }
                ILibWrapper_StopChain(mChain);
                if (!mChainThread.Equals(Thread.CurrentThread))
                {
                    mChainThread.Join();
                }
            }
            /// <summary>
            /// Returns true, if the Microstack Chain has been started
            /// </summary>
            public bool Running
            {
                get
                {
                    return (ILibWrapper_IsChainRunning(mChain) == 0 ? false : true);
                }
            }

            /// <summary>
            /// Returns true, if the Microstack chain is shutting down
            /// </summary>
            public bool ShuttingDown
            {
                get
                {
                    return (ILibWrapper_DLL_IsChainDisposing(mChain) == 0 ? false : true);
                }
            }

            /// <summary>
            /// Initializes a new instance of a Wrapper Class for Microstack
            /// </summary>
            public MicrostackChain()
            {
                mChain = ILibWrapper_CreateMicrostackChain();
                mBaseTimer = ILibWrapper_DLL_GetBaseTimer(mChain);
                nLifetimeExpireSink = LifetimeExpireSink;
                nLifetimeDestroySink = LifetimeDestroySink;
            }
            ~MicrostackChain()
            {
                Dispose();
            }

            /// <summary>
            /// Releases all resources associated with the Microstack chain
            /// </summary>
            public void Dispose()
            {
                if (!disposing)
                {
                    disposing = true;
                    if (Running)
                    {
                        StopChain();
                    }
                }
            }
            #endregion
        }
    }

    #region WebRTCConnection Abstraction


    /// <summary>
    /// A WebRTCConnection object that can be used to facilitate WebRTC Data communications
    /// </summary>
    public class WebRTCConnection : IDisposable
    {
        public enum TURN_Connect_Flags
        {
	        DISABLED = 0,		//!< No TURN support
	        ENABLED = 1,		//!< Always connect the control channel, but only use the server when necessary
	        ALWAYS_RELAY = 2	//!< Always relay all connections
        } 
        public static void RemoteLog(WebRTCCommons.MicrostackChain.RemoteLogging_Modules module, WebRTCCommons.MicrostackChain.RemoteLogging_Flags flag, string msg)
        {
            if(Chain != null)
            {
                Chain.RemoteLog(module, flag, msg);
            }
        }
        private static bool mForce = false;
        public static bool ChainAlwaysRunning
        {
            get
            {
                return (mForce);
            }
            set
            {
                mForce = value;
                if (Chain == null && value)
                {
                    Chain = new WebRTCCommons.MicrostackChain();
                    nConnectionFactory = ILibWrapper_DLL_WebRTC_ConnectionFactory_CreateConnectionFactory(Chain.mChain, 0);
                    Chain.StartChain();
                }
                if (!value)
                {
                    lock (Connections)
                    {
                        if (Connections.Count == 0)
                        {
                            Chain.Dispose();
                            Chain = null;
                        }
                    }
                }
            }
        }
        public static ushort StartDefaultLogger(ushort port)
        {
            if (nConnectionFactory != IntPtr.Zero)
            {
                return (ILibWrapper_DLL_WebRTC_StartDefaultLogger(nConnectionFactory, port));
            }
            else
            {
                return (0);
            }
        }
#if DEBUG_EVENTS
        private bool mConnected = false;
#endif
        private static WebRTCCommons.MicrostackChain Chain = null;
        private static IntPtr nConnectionFactory;

        #region ConnectionFactory

        #region P-Invoke/Declarations

        #region Function Pointers
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void ILibWrapper_WebRTC_Connection_OnConnect(IntPtr connection, int connected);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void ILibWrapper_WebRTC_Connection_OnDataChannel(IntPtr connection, [MarshalAs(UnmanagedType.Struct)] ref NativeDataChannel dataChannel);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void ILibWrapper_WebRTC_Connection_OnSendOK(IntPtr connection);
        #endregion

        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr ILibWrapper_DLL_WebRTC_ConnectionFactory_CreateConnectionFactory(IntPtr chain, ushort localPort);

        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr ILibWrapper_DLL_WebRTC_ConnectionFactory_CreateConnection(IntPtr factory, ILibWrapper_WebRTC_Connection_OnConnect OnConnectHandler, ILibWrapper_WebRTC_Connection_OnDataChannel OnDataChannelHandler, ILibWrapper_WebRTC_Connection_OnSendOK OnConnectionSendOK);

        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern ushort ILibWrapper_DLL_WebRTC_StartDefaultLogger(IntPtr factory, ushort port);

        #endregion
        
        #endregion
        #region Native WebRTC DataChannel Structure

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct NativeDataChannel
        {
            /*
            *
            * DO NOT MODIFY STRUCT DEFINITION
            *
            */
            public ILibWrapper_WebRTC_DataChannel_OnData OnBinaryData;
            public ILibWrapper_WebRTC_DataChannel_OnData OnStringData;
            public ILibWrapper_WebRTC_DataChannel_OnRawData OnRawData;
            public IntPtr Chain;
            public IntPtr ReservedMemory;
            public IntPtr SendPtr;
            public IntPtr ClosePtr;
            public IntPtr PendingBytesPtr;
            public IntPtr TransportSendOkPtr;
            public UInt32 IdentifierFlags;

            public ushort streamId;
            public IntPtr channelName;

            public ILibWrapper_WebRTC_DataChannel_OnDataChannel OnAck;
            public ILibWrapper_WebRTC_DataChannel_OnClosed OnClosed;
            public IntPtr parent;
            public IntPtr userData;

            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate void ILibWrapper_WebRTC_DataChannel_OnData([MarshalAs(UnmanagedType.Struct)] ref NativeDataChannel dataChannel, IntPtr data, int dataLen);
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate void ILibWrapper_WebRTC_DataChannel_OnRawData([MarshalAs(UnmanagedType.Struct)] ref NativeDataChannel dataChannel, IntPtr data, int dataLen, int dataType);
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate void ILibWrapper_WebRTC_DataChannel_OnDataChannel([MarshalAs(UnmanagedType.Struct)] ref NativeDataChannel dataChannel);
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate void ILibWrapper_WebRTC_DataChannel_OnClosed([MarshalAs(UnmanagedType.Struct)] ref NativeDataChannel dataChannel);
        }
        #endregion
        #region P-Invoke Declarations
        #region Function Pointers
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void ILibWrapper_WebRTC_OnConnectionCandidate(IntPtr connection, IntPtr candidate);
        
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void ILibWrapper_WebRTC_DataChannel_OnDataChannelAck([MarshalAs(UnmanagedType.Struct)] ref NativeDataChannel dataChannel);
        #endregion
        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr ILibWrapper_DLL_WebRTC_Connection_GenerateOffer(IntPtr connection, ILibWrapper_WebRTC_OnConnectionCandidate onCandidates);
        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr ILibWrapper_DLL_WebRTC_Connection_SetOffer(IntPtr connection, IntPtr offer, int offerLen, ILibWrapper_WebRTC_OnConnectionCandidate onCandidates);
        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr ILibWrapper_DLL_WebRTC_Connection_AddServerReflexiveCandidateToLocalSDP(IntPtr connection, IntPtr candidate);
        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern void ILibWrapper_DLL_WebRTC_Connection_SetUserData(IntPtr connection, IntPtr user1, IntPtr user2, IntPtr user3);
        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern void ILibWrapper_DLL_WebRTC_Connection_GetUserData(IntPtr connection, ref IntPtr user1, ref IntPtr user2, ref IntPtr user3);

        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern void ILibWrapper_DLL_WebRTC_Connection_Disconnect(IntPtr connection);

        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern void ILibWrapper_DLL_WebRTC_Connection_Pause(IntPtr connection);
        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern void ILibWrapper_DLL_WebRTC_Connection_Resume(IntPtr connection);

        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern void ILibWrapper_DLL_WebRTC_Connection_SetStunServers(IntPtr connection, [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPStr)] string[] serverList, int serverLength);

        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern void ILibWrapper_DLL_WebRTC_ConnectionFactory_SetTurnServer(IntPtr factory, IntPtr turnServer, IntPtr username, IntPtr password, TURN_Connect_Flags turnSetting);

        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern void ILibWrapper_DLL_WebRTC_Connection_AddRemoteCandidate(IntPtr connection, IntPtr candidate);
        #endregion

        #region Debug Events
#if DEBUG_EVENTS
        private ILibWrapper_WebRTC_Connection_OnDebugEvent nDebugEventSink = null;
        private void DebugEventSink(IntPtr connection, string debugField, int debugValue)
        {
            switch (debugField)
            {
                case "OnHold":
                    if (_DebugEvents_OnHold != null) { _DebugEvents_OnHold(this, debugValue); }
                    break;
                case "OnReceiverCredits":
                    if (_DebugEvents_OnReceiverCredits != null) { _DebugEvents_OnReceiverCredits(this, debugValue); }
                    break;
                case "OnSendFastRetry":
                    if (_DebugEvents_OnSendFastRetry != null) { _DebugEvents_OnSendFastRetry(this, debugValue); }
                    break;
                case "OnSendRetry":
                    if (_DebugEvents_OnSendRetry != null) { _DebugEvents_OnSendRetry(this, debugValue); }
                    break;
                case "OnCongestionWindowSizeChanged":
                    if (_DebugEvents_OnCongestionWindowSizeChanged != null) { _DebugEvents_OnCongestionWindowSizeChanged(this, debugValue); }
                    break;
                case "OnSACKReceived":
                    if (_DebugEvents_OnSACKReceived != null) { _DebugEvents_OnSACKReceived(this, (uint)debugValue); }
                    break;
                case "OnFastRecovery":
                    if (_DebugEvents_OnFastRecovery != null) { _DebugEvents_OnFastRecovery(this, debugValue != 0); }
                    break;
                case "OnT3RTX":
                    if (_DebugEvents_OnT3RTX != null) { _DebugEvents_OnT3RTX(this, debugValue < 0, debugValue > 0, debugValue); }
                    break;
                case "OnRTTCalculated":
                    if (_DebugEvents_OnRTTCalculated != null) { _DebugEvents_OnRTTCalculated(this, debugValue); }
                    break;
                case "OnTSNFloorNotRaised":
                    if (_DebugEvents_OnTSNFloorNotRaised != null) { _DebugEvents_OnTSNFloorNotRaised(this, debugValue); }
                    break;
            }
        }
        public delegate void DebugEvents_OnHoldHandler(WebRTCConnection sender, int holdCount);
        private event DebugEvents_OnHoldHandler _DebugEvents_OnHold;
        public event DebugEvents_OnHoldHandler DebugEvents_OnHold
        {
            add
            {
                _DebugEvents_OnHold += value;
                SetDebug(nConnection, "OnHold", nDebugEventSink);
            }
            remove
            {
                _DebugEvents_OnHold -= value;
            }
        }

        public delegate void DebugEvents_OnReceiverCreditsHandler(WebRTCConnection sender, int receiverCredits);
        private event DebugEvents_OnReceiverCreditsHandler _DebugEvents_OnReceiverCredits;
        public event DebugEvents_OnReceiverCreditsHandler DebugEvents_OnReceiverCredits
        {
            remove
            {
                _DebugEvents_OnReceiverCredits -= value;
            }
            add
            {
                _DebugEvents_OnReceiverCredits += value;
                SetDebug(nConnection, "OnReceiverCredits", nDebugEventSink);
            }
        }

        public delegate void DebugEvents_OnSendRetryHandler(WebRTCConnection sender, int retryCount);
        private event DebugEvents_OnSendRetryHandler _DebugEvents_OnSendFastRetry;
        public event DebugEvents_OnSendRetryHandler DebugEvents_OnSendFastRetry
        {
            remove
            {
                _DebugEvents_OnSendFastRetry -= value;
            }
            add
            {
                _DebugEvents_OnSendFastRetry += value;
                SetDebug(nConnection, "OnSendFastRetry", nDebugEventSink);
            }
        }

        private event DebugEvents_OnSendRetryHandler _DebugEvents_OnSendRetry;
        public event DebugEvents_OnSendRetryHandler DebugEvents_OnSendRetry
        {
            remove
            {
                _DebugEvents_OnSendRetry -= value;
            }
            add
            {
                _DebugEvents_OnSendRetry += value;
                SetDebug(nConnection, "OnSendRetry", nDebugEventSink);
            }
        }

        public delegate void DebugEvents_OnCongestionWindowSizeChangedHandler(WebRTCConnection sender, int windowSize);
        private event DebugEvents_OnCongestionWindowSizeChangedHandler _DebugEvents_OnCongestionWindowSizeChanged;
        public event DebugEvents_OnCongestionWindowSizeChangedHandler DebugEvents_OnCongestionWindowSizeChanged
        {
            remove
            {
                _DebugEvents_OnCongestionWindowSizeChanged -= value;
            }
            add
            {
                _DebugEvents_OnCongestionWindowSizeChanged += value;
                SetDebug(nConnection, "OnCongestionWindowSizeChanged", nDebugEventSink);
            }
        }

        public delegate void DebugEvents_OnSACKReceivedHandler(WebRTCConnection sender, uint TSN);
        private event DebugEvents_OnSACKReceivedHandler _DebugEvents_OnSACKReceived;
        public event DebugEvents_OnSACKReceivedHandler DebugEvents_OnSACKReceived
        {
            remove
            {
                _DebugEvents_OnSACKReceived -= value;
            }
            add
            {
                _DebugEvents_OnSACKReceived += value;
                SetDebug(nConnection, "OnSACKReceived", nDebugEventSink);
            }
        }

        public delegate void DebugEvents_OnRTTCalculatedHandler(WebRTCConnection sender, int SRTT);
        private event DebugEvents_OnRTTCalculatedHandler _DebugEvents_OnRTTCalculated;
        public event DebugEvents_OnRTTCalculatedHandler DebugEvents_OnRTTCalculated
        {
            remove
            {
                _DebugEvents_OnRTTCalculated -= value;
            }
            add
            {
                _DebugEvents_OnRTTCalculated += value;
                SetDebug(nConnection, "OnRTTCalculated", nDebugEventSink);
            }
        }

        public delegate void DebugEvents_OnFastRecoveryHandler(WebRTCConnection sender, bool EnterFastRecovery);
        private event DebugEvents_OnFastRecoveryHandler _DebugEvents_OnFastRecovery;
        public event DebugEvents_OnFastRecoveryHandler DebugEvents_OnFastRecovery
        {
            remove
            {
                _DebugEvents_OnFastRecovery -= value;
            }
            add
            {
                _DebugEvents_OnFastRecovery += value;
                SetDebug(nConnection, "OnFastRecovery", nDebugEventSink);
            }
        }

        public delegate void DebugEvents_OnT3RTXHandler(WebRTCConnection sender, bool IsExpired, bool IsEnabled, int RTOValue);
        private event DebugEvents_OnT3RTXHandler _DebugEvents_OnT3RTX;
        public event DebugEvents_OnT3RTXHandler DebugEvents_OnT3RTX
        {
            remove
            {
                _DebugEvents_OnT3RTX -= value;
            }
            add
            {
                _DebugEvents_OnT3RTX += value;
                SetDebug(nConnection, "OnT3RTX", nDebugEventSink);
            }
        }

        public delegate void DebugEvents_OnTSNFloorNotRaisedHandler(WebRTCConnection sender, int resendCounter);
        private event DebugEvents_OnTSNFloorNotRaisedHandler _DebugEvents_OnTSNFloorNotRaised;
        public event DebugEvents_OnTSNFloorNotRaisedHandler DebugEvents_OnTSNFloorNotRaised
        {
            remove
            {
                _DebugEvents_OnTSNFloorNotRaised -= value;
            }
            add
            {
                _DebugEvents_OnTSNFloorNotRaised += value;
                SetDebug(nConnection, "OnTSNFloorNotRaised", nDebugEventSink);
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void ILibWrapper_WebRTC_Connection_OnDebugEvent(IntPtr connection, [MarshalAs(UnmanagedType.LPStr)] string debugFieldName, int debugValue);
        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern int ILibWrapper_DLL_SCTP_Debug_SetDebug(IntPtr Connection, [MarshalAs(UnmanagedType.LPStr)] string debugFieldName, ILibWrapper_WebRTC_Connection_OnDebugEvent eventHandler);
        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern void ILibWrapper_DLL_WebRTC_ConnectionFactory_SetSimulatedLossPercentage(IntPtr factory, int lossPercentage);
        
        private int SetDebug(IntPtr Connection, string debugFieldName, ILibWrapper_WebRTC_Connection_OnDebugEvent eventHandler)
        {
            if (mConnected == false) { throw (new Exception("Can't attach debug events unless the WebRTCConnection is connected!")); }
            return (ILibWrapper_DLL_SCTP_Debug_SetDebug(Connection, debugFieldName, eventHandler));
        }

        public void _Debug_SetLossPercentage(int value)
        {
            ILibWrapper_DLL_WebRTC_ConnectionFactory_SetSimulatedLossPercentage(nConnectionFactory, value);
        }
#endif
        #endregion

        public delegate void ConnectionSendOkHandler(WebRTCConnection sender);
        public event ConnectionSendOkHandler OnConnectionSendOk;

        public List<WebRTCDataChannel> DataChannels = new List<WebRTCDataChannel>();
        public delegate void DataChannelHandler(WebRTCConnection sender, WebRTCDataChannel dataChannel);
        public event DataChannelHandler OnDataChannel;

        public delegate void ConnectHandler(WebRTCConnection sender);
        public event ConnectHandler OnConnected;
        public event ConnectHandler OnDisconnected;
        private CandidateHandler mCandidateSink,mCandidateSink2;

        public delegate void CandidateHandler(WebRTCConnection sender, IPEndPoint candidate);

        public readonly IntPtr nConnection;
        private ILibWrapper_WebRTC_Connection_OnConnect nConnectSink;
        private ILibWrapper_WebRTC_Connection_OnDataChannel nDataChannelSink;
        private ILibWrapper_WebRTC_Connection_OnSendOK nSendOKSink;
        private ILibWrapper_WebRTC_OnConnectionCandidate nCandidateSink, nCandidateSink2, nCandidateSink_Awaiter;

        private static HashSet<WebRTCConnection> Connections = new HashSet<WebRTCConnection>();

        public WebRTCCommons.MicrostackChain Root
        {
            get
            {
                return (Chain);
            }
        }

        public static void ConfigureTURN(IPEndPoint server, string username, string password, TURN_Connect_Flags flags = TURN_Connect_Flags.ENABLED)
        {
            if (flags != TURN_Connect_Flags.DISABLED) { WebRTCConnection.ChainAlwaysRunning = true; }
            IntPtr turnPtr = server != null ? WebRTCCommons.GetSockAddr(server) : IntPtr.Zero;
            IntPtr turnUsername = username != null ? Marshal.StringToHGlobalAnsi(username) : IntPtr.Zero;
            IntPtr turnPassword = password != null ? Marshal.StringToHGlobalAnsi(password) : IntPtr.Zero;

            WebRTCConnection.ILibWrapper_DLL_WebRTC_ConnectionFactory_SetTurnServer(nConnectionFactory, turnPtr, turnUsername, turnPassword, flags);

            WebRTCCommons.FreeSockAddr(turnPtr);
            if (username != null) { Marshal.FreeHGlobal(turnUsername); }
            if (password != null) { Marshal.FreeHGlobal(turnPassword); }
        }

        /// <summary>
        /// Creates a new WebRTCConnection object
        /// </summary>
        /// <returns></returns>
        public static WebRTCConnection Create()
        {
            return (new WebRTCConnection());
        }
        /// <summary>
        /// Creates a new WebRTCConnection object
        /// </summary>
        public WebRTCConnection()
        {
            if (Chain == null)
            {
                Chain = new WebRTCCommons.MicrostackChain();
                nConnectionFactory = ILibWrapper_DLL_WebRTC_ConnectionFactory_CreateConnectionFactory(Chain.mChain, 0);
                Chain.StartChain();
            }
           
            nConnectSink = ConnectSink;
            nDataChannelSink = DataChannelSink;
            nSendOKSink = SendOKSink;
            nCandidateSink = CandidateSink;
            nCandidateSink2 = CandidateSink2;
            nCandidateSink_Awaiter = CandidateSink_Awaiter;

#if DEBUG_EVENTS
            nDebugEventSink = DebugEventSink;
#endif
            nConnection = ILibWrapper_DLL_WebRTC_ConnectionFactory_CreateConnection(nConnectionFactory, nConnectSink, nDataChannelSink, nSendOKSink);
            lock (Connections)
            {
               Connections.Add(this);
            }
        }

        private void SetData<T, T2, T3>(T val1, T2 val2, T3 val3)
        {
            IntPtr v1,v2,v3;

            v1 = val1 != null ? Marshal.GetIUnknownForObject(val1) : IntPtr.Zero;
            v2 = val2 != null ? Marshal.GetIUnknownForObject(val2) : IntPtr.Zero;
            v3 = val3 != null ? Marshal.GetIUnknownForObject(val3) : IntPtr.Zero;

            ILibWrapper_DLL_WebRTC_Connection_SetUserData(nConnection, v1, v2, v3);
        }
        private void GetData<T, T2, T3>(out T val1, out T2 val2, out T3 val3)
        {
            IntPtr v1=IntPtr.Zero, v2=IntPtr.Zero, v3=IntPtr.Zero;

            ILibWrapper_DLL_WebRTC_Connection_GetUserData(nConnection, ref v1, ref v2, ref v3);

            val1 = (T) (v1.Equals(IntPtr.Zero) ? null : Marshal.GetObjectForIUnknown(v1));
            val2 = (T2) (v2.Equals(IntPtr.Zero) ? null : Marshal.GetObjectForIUnknown(v2));
            val3 = (T3) (v3.Equals(IntPtr.Zero) ? null : Marshal.GetObjectForIUnknown(v3));

            if (!v1.Equals(IntPtr.Zero)) { Marshal.Release(v1); }
            if (!v2.Equals(IntPtr.Zero)) { Marshal.Release(v2); }
            if (!v3.Equals(IntPtr.Zero)) { Marshal.Release(v3); }
        }

        private void ConnectSink(IntPtr connection, int connected)
        {
            WebRTCConnection.RemoteLog(WebRTCCommons.MicrostackChain.RemoteLogging_Modules.WebRTC_SCTP, WebRTCCommons.MicrostackChain.RemoteLogging_Flags.VerbosityLevel_1, "C#: ConnectSink");
            if (connected != 0)
            {
#if DEBUG_EVENTS
                mConnected = true;
#endif
                if (OnConnected != null) { OnConnected(this); }
            }
            else
            {
#if DEBUG_EVENTS
                mConnected = false;
#endif
                if (OnDisconnected != null) { OnDisconnected(this); }
                Dispose();
            }
        }
       
        private void DataChannelSink(IntPtr connection, ref NativeDataChannel dataChannel)
        {
            WebRTCDataChannel dc = WebRTCDataChannel.Create(this, ref dataChannel);
            lock (DataChannels)
            {
                DataChannels.Add(dc);
            }
            dc.SetComplete(dc);

            if (OnDataChannel != null)
            {
                OnDataChannel(this, dc);
            }
        }

        private void SendOKSink(IntPtr connection)
        {
            if (OnConnectionSendOk != null) { OnConnectionSendOk(this); }
        }
        private void CandidateSink(IntPtr connection, IntPtr candidate)
        {
            if (mCandidateSink != null)
            {
                mCandidateSink(this, candidate.Equals(IntPtr.Zero)?null:WebRTCCommons.GetIPEndPoint(candidate));
            }
        }
        private void CandidateSink2(IntPtr connection, IntPtr candidate)
        {
            if (mCandidateSink2 != null)
            {
                mCandidateSink2(this, candidate.Equals(IntPtr.Zero) ? null : WebRTCCommons.GetIPEndPoint(candidate));
            }
        }
        private void CandidateSink_Awaiter(IntPtr connection, IntPtr candidate)
        {
            WebRTCCommons.CustomAwaiter<string> awaiter;
            object v2, v3;

            GetData<WebRTCCommons.CustomAwaiter<string>, object, object>(out awaiter, out v2, out v3);
            IntPtr noffer = ILibWrapper_DLL_WebRTC_Connection_AddServerReflexiveCandidateToLocalSDP(connection, candidate);
            string offer = Marshal.PtrToStringAnsi(noffer);
            WebRTCCommons.FreeSockAddr(noffer);

            awaiter.SetComplete(offer);
        }
        bool disposing = false;
        public void Dispose()
        {
            if (!disposing)
            {
                disposing = true;
                ILibWrapper_DLL_WebRTC_Connection_Disconnect(nConnection);

                lock (Connections)
                {
                    Connections.Remove(this);
                    if (Connections.Count == 0 && !mForce)
                    {
                        Chain.Dispose();
                        Chain = null;
                    }
                }
            }
        }

        /// <summary>
        /// An awaitable method to generate an initial WebRTC offer to exchange with a peer.
        /// The awaitable result is the complete offer string with all candidates
        /// </summary>
        public WebRTCCommons.CustomAwaiter<string> GenerateOffer()
        {
            WebRTCCommons.CustomAwaiter<string> retVal = new WebRTCCommons.CustomAwaiter<string>();
            SetData<WebRTCCommons.CustomAwaiter<string>, object, object>(retVal, null, null);

            IntPtr i = ILibWrapper_DLL_WebRTC_Connection_GenerateOffer(nConnection, nCandidateSink_Awaiter);      
            WebRTCCommons.FreeSockAddr(i);
            return (retVal);
        }

        /// <summary>
        /// A method to generate an initial WebRTC offer to exchange with a peer.
        /// Returns a string offer with only the local-host-generated/relayed candidates
        /// </summary>
        /// <param name="candidateSink">Called for each non-host-generated/relayed candidate as they are discovered</param>
        public string GenerateOffer(CandidateHandler candidateSink)
        {
            mCandidateSink = candidateSink;
            IntPtr i = ILibWrapper_DLL_WebRTC_Connection_GenerateOffer(nConnection, nCandidateSink);
            string retVal = Marshal.PtrToStringAnsi(i);
            WebRTCCommons.FreeSockAddr(i);
            return (retVal);
        }

        /// <summary>
        /// A method to set the peer's offer/answer during a WebRTC offer exchange.
        /// Returns a string offer response with only the local-host-generated/relayed candidates
        /// </summary>
        /// <param name="offer">The offer to set</param>
        /// <param name="candidateSink">Called for each non-host-genreated/relayed candidate as they are discovered</param>
        public string SetOffer(string offer, CandidateHandler candidateSink)
        {
            mCandidateSink2 = candidateSink;
            IntPtr nOffer = Marshal.StringToHGlobalAnsi(offer);
            IntPtr i = ILibWrapper_DLL_WebRTC_Connection_SetOffer(nConnection, nOffer, offer.Length, nCandidateSink2);
            string retVal = Marshal.PtrToStringAnsi(i);
            WebRTCCommons.FreeSockAddr(i);
            return (retVal);
        }

        /// <summary>
        /// An awaitable method to set the peer's offer/answer during a WebRTC offer exchange.
        /// The awaitable result is the complete string offer response with all candidates.
        /// </summary>
        /// <param name="offer">The offer to set</param>
        public WebRTCCommons.CustomAwaiter<string> SetOffer(string offer)
        {
            WebRTCCommons.CustomAwaiter<string> retVal = new WebRTCCommons.CustomAwaiter<string>();
            SetData<WebRTCCommons.CustomAwaiter<string>, object, object>(retVal, null, null);

            IntPtr noffer = Marshal.StringToHGlobalAnsi(offer);
            IntPtr i = ILibWrapper_DLL_WebRTC_Connection_SetOffer(nConnection, noffer, offer.Length, nCandidateSink_Awaiter);
            WebRTCCommons.FreeSockAddr(i);
            return (retVal);
        }

        public void AddRemoteCandidate(IPEndPoint candidate)
        {
            IntPtr nSock = WebRTCCommons.GetSockAddr(candidate);
            ILibWrapper_DLL_WebRTC_Connection_AddRemoteCandidate(nConnection, nSock);
            WebRTCCommons.FreeSockAddr(nSock);
        }

        /// <summary>
        /// A helper method that will add server-reflexive candidates to the local offer, so that an updated offer can be sent to the remote peer.
        /// Returns an updated offer containing the server-reflexive candidate specified
        /// </summary>
        /// <param name="candidate">Server-Reflexive candidate to add</param>
        public string UpdateLocalSDPWithServerReflexiveCandidate(IPEndPoint candidate)
        {
            IntPtr nSock = WebRTCCommons.GetSockAddr(candidate);
            IntPtr i = ILibWrapper_DLL_WebRTC_Connection_AddServerReflexiveCandidateToLocalSDP(nConnection, nSock);
            WebRTCCommons.FreeSockAddr(nSock);
            string retVal = Marshal.PtrToStringAnsi(i);
            WebRTCCommons.FreeSockAddr(i);
            return (retVal);
        }

        /// <summary>
        /// Optionally sets a list of stunServers in dotted quad notation to be used by WebRTC. If port numbers are not specified, the default STUN port is assumed (3478)
        /// </summary>
        /// <param name="stunServers"></param>
        public void SetStunServers(params string[] stunServers)
        {
            ILibWrapper_DLL_WebRTC_Connection_SetStunServers(nConnection, stunServers, stunServers.Length);
        }

        /// <summary>
        /// An awaitable method to create a new WebRTC Data Channel object.
        /// Returns the created WebRTCDataChannel. If awaited, the result will be a bool denoting if it was ACK'ed by the remote peer
        /// </summary>
        /// <param name="channelName">Friendly name of the channel to create</param>
        /// <param name="streamId">Manually specified streamId. If not specified, a suitable one is automatically chosen</param>
        public WebRTCDataChannel CreateDataChannel(string channelName, int streamId = -1)
        {
            return (WebRTCDataChannel.Create(this, channelName, streamId));
        }

        /// <summary>
        /// Pauses the processing of inbound data for all DataChannels
        /// </summary>
        public void Pause()
        {
            ILibWrapper_DLL_WebRTC_Connection_Pause(nConnection);
        }

        /// <summary>
        /// Resumes processing of inbound data for all DataChannels
        /// </summary>
        public void Resume()
        {
            ILibWrapper_DLL_WebRTC_Connection_Resume(nConnection);
        }


    }
    #endregion

    #region DataChannel Abstraction
    /// <summary>
    /// A WebRTC Data Channel
    /// </summary>
    public class WebRTCDataChannel : WebRTCCommons.CustomAwaiter<WebRTCDataChannel>
    {
        #region Native Function Pointers/Handlers
        private WebRTCConnection.NativeDataChannel.ILibWrapper_WebRTC_DataChannel_OnData OnBinaryDataSink, OnStringDataSink;
        private WebRTCConnection.NativeDataChannel.ILibWrapper_WebRTC_DataChannel_OnRawData OnRawDataSink;
        private WebRTCConnection.NativeDataChannel.ILibWrapper_WebRTC_DataChannel_OnClosed OnClosedSink;


        private void BinaryDataSink(ref WebRTCConnection.NativeDataChannel dataChannel, IntPtr data, int dataLen)
        {
            if (OnBinaryReceiveData != null)
            {
                byte[] mData = new byte[dataLen];
                Marshal.Copy(data, mData, 0, dataLen);
                OnBinaryReceiveData(this, mData);
            }
        }
        private void StringDataSink(ref WebRTCConnection.NativeDataChannel dataChannel, IntPtr data, int dataLen)
        {
            if (OnStringReceiveData != null)
            {
                OnStringReceiveData(this, Marshal.PtrToStringAnsi(data, dataLen));
            }
        }
        private void RawDataSink(ref WebRTCConnection.NativeDataChannel dataChannel, IntPtr data, int dataLen, int dataType)
        {
            if (OnRawReceiveData != null)
            {
                byte[] mData = new byte[dataLen];
                Marshal.Copy(data, mData, 0, dataLen);
                OnRawReceiveData(this, mData, dataType);
            }
        }
        private void ClosedSink(ref WebRTCConnection.NativeDataChannel dataChannel)
        {
            // When this is called, this object is going away, so we need to clean up

            WebRTCDataChannel dc = Marshal.GetObjectForIUnknown(dataChannel.userData) as WebRTCDataChannel;
            if (dc != null)
            {
                if (dc.OnClosing != null)
                {
                    dc.OnClosing(dc);
                }
                Marshal.Release(dataChannel.userData);
            }
        }
        #endregion

        /// <summary>
        /// An enumeration specifying the send result
        /// </summary>
        public enum SendStatus
        {
            /// <summary>
            /// All of the data has already been sent
            /// </summary>
            ALL_DATA_SENT = 0, 
            /// <summary>
            /// Not all of the data could be sent, but is queued to be sent as soon as possible
            /// </summary>
	        NOT_ALL_DATA_SENT_YET = 1, 
            /// <summary>
            /// A send operation was attmepted on a closed socket 
            /// </summary>
	        SEND_ON_CLOSED_SOCKET_ERROR	= -4 
        }

        #region P-Invoke Declarations
        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern SendStatus ILibWrapper_DLL_WebRTC_DataChannel_Send([MarshalAs(UnmanagedType.Struct)] ref WebRTCConnection.NativeDataChannel dataChannel, IntPtr data, int dataLen);
        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern SendStatus ILibWrapper_DLL_WebRTC_DataChannel_SendEx([MarshalAs(UnmanagedType.Struct)] ref WebRTCConnection.NativeDataChannel dataChannel, IntPtr data, int dataLen, int dataType);
        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern SendStatus ILibWrapper_DLL_WebRTC_DataChannel_SendString([MarshalAs(UnmanagedType.Struct)] ref WebRTCConnection.NativeDataChannel dataChannel, IntPtr data, int dataLen);

        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr ILibWrapper_DLL_WebRTC_DataChannel_Create(IntPtr connection, IntPtr channelName, int channelNameLen, WebRTCConnection.NativeDataChannel.ILibWrapper_WebRTC_DataChannel_OnDataChannel OnAckHandler, IntPtr user);
        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr ILibWrapper_DLL_WebRTC_DataChannel_CreateEx(IntPtr connection, IntPtr channelName, int channelNameLen, ushort streamId, WebRTCConnection.NativeDataChannel.ILibWrapper_WebRTC_DataChannel_OnDataChannel OnAckHandler, IntPtr user);
        [DllImport("WebRTC.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.Cdecl)]
        private static extern void ILibWrapper_DLL_WebRTC_DataChannel_Close([MarshalAs(UnmanagedType.Struct)] ref WebRTCConnection.NativeDataChannel dataChannel);        
        #endregion

        public readonly WebRTCConnection ParentConnection;
        private WebRTCConnection.NativeDataChannel nDataChannel;
        private WebRTCConnection.NativeDataChannel.ILibWrapper_WebRTC_DataChannel_OnDataChannel nDataChannelAck;
        

        public delegate void StringDataHandler(WebRTCDataChannel sender, string data);
        public delegate void BinaryDataHandler(WebRTCDataChannel sender, byte[] data);
        public delegate void RawDataHandler(WebRTCDataChannel sender, byte[] data, int dataType);
       
        /// <summary>
        /// An event that is raised whenever string data was received
        /// </summary>
        public event StringDataHandler OnStringReceiveData;
        /// <summary>
        /// An event that is raised whenever binary data was received
        /// </summary>
        public event BinaryDataHandler OnBinaryReceiveData;
        /// <summary>
        /// An event that is raised whenever any type of data was received
        /// </summary>
        public event RawDataHandler OnRawReceiveData;

        public delegate void OnClosingHandler(WebRTCDataChannel sender);

        /// <summary>
        /// An event that is raised when the Data Channel is closing
        /// </summary>
        public event OnClosingHandler OnClosing;

        /// <summary>
        /// The friendly name associated with this Data Channel
        /// </summary>
        public string ChannelName
        {
            get
            {
                return (mChannelName);
            }
        }
        private string mChannelName = "";
        /// <summary>
        /// The stream ID of this data channel
        /// </summary>
        public ushort StreamId
        {
            get
            {
                return (nDataChannel.streamId);
            }
        }

        private void DataChannelAckSink(ref WebRTCConnection.NativeDataChannel dataChannel)
        {
            WebRTCDataChannel mDataChannel = (WebRTCDataChannel)Marshal.GetObjectForIUnknown(dataChannel.userData);
            mDataChannel.ParentConnection.Root.RemoveLifeTime(mDataChannel);

            SetNative(ref dataChannel);

            mDataChannel.SetComplete(mDataChannel);
        }
        private void SetNative(ref WebRTCConnection.NativeDataChannel nativeDataChannel)
        {
            nDataChannel = nativeDataChannel;
            mChannelName = Marshal.PtrToStringAnsi(nDataChannel.channelName);
            nativeDataChannel.userData = Marshal.GetIUnknownForObject(this);

            nativeDataChannel.OnBinaryData = OnBinaryDataSink;
            nativeDataChannel.OnStringData = OnStringDataSink;
            nativeDataChannel.OnRawData = OnRawDataSink;
            nativeDataChannel.OnClosed = OnClosedSink;
        }
        private WebRTCDataChannel(WebRTCConnection Parent)
        {
            ParentConnection = Parent;
            OnBinaryDataSink = BinaryDataSink;
            OnStringDataSink = StringDataSink;
            OnRawDataSink = RawDataSink;
            OnClosedSink = ClosedSink;
            nDataChannelAck = DataChannelAckSink;
        }
        public static WebRTCDataChannel Create(WebRTCConnection Parent, ref WebRTCConnection.NativeDataChannel nativeDataChannel)
        {
            WebRTCDataChannel retVal = new WebRTCDataChannel(Parent);
            retVal.SetNative(ref nativeDataChannel);
            return (retVal);
        }
        public static WebRTCDataChannel Create(WebRTCConnection Parent, string NewChannelName, int streamId = -1)
        {
            WebRTCDataChannel retVal = new WebRTCDataChannel(Parent);

            retVal.ParentConnection.Root.AddLifeTime(retVal, 5000, (WebRTCCommons.MicrostackChain.LifeTimeExpirationHandler)((sender, ExpiredData) =>
            {
                (ExpiredData as WebRTCDataChannel).SetComplete(null);
            }), null);

            IntPtr name = Marshal.StringToHGlobalAnsi(NewChannelName);
            IntPtr ptrDataChannel = streamId < 0 ? ILibWrapper_DLL_WebRTC_DataChannel_Create(retVal.ParentConnection.nConnection, name, NewChannelName.Length, retVal.nDataChannelAck, Marshal.GetIUnknownForObject(retVal)) : ILibWrapper_DLL_WebRTC_DataChannel_CreateEx(retVal.ParentConnection.nConnection, name, NewChannelName.Length, (ushort)streamId, retVal.nDataChannelAck, Marshal.GetIUnknownForObject(retVal));

            lock (retVal.ParentConnection.DataChannels)
            {
                retVal.ParentConnection.DataChannels.Add(retVal);
            }

            return (retVal);
        }
        public void Close()
        {
            ILibWrapper_DLL_WebRTC_DataChannel_Close(ref nDataChannel);
        }

        /// <summary>
        /// Send string data
        /// </summary>
        /// <param name="data">String data to send</param>
        /// <returns>Send status</returns>
        public SendStatus Send(string data)
        {
            if (ParentConnection.Root.ShuttingDown) { return (SendStatus.SEND_ON_CLOSED_SOCKET_ERROR); }
            IntPtr nData = Marshal.StringToHGlobalAnsi(data);
            SendStatus retVal = ILibWrapper_DLL_WebRTC_DataChannel_SendString(ref nDataChannel, nData, data.Length);
            Marshal.FreeHGlobal(nData);
            return (retVal);
        }
        /// <summary>
        /// Send binary data
        /// </summary>
        /// <param name="data">Binary data to send</param>
        /// <returns>Send status</returns>
        public SendStatus Send(byte[] data)
        {
            return (Send(data, 0, data.Length));
        }

        /// <summary>
        /// Send binary data
        /// </summary>
        /// <param name="data">Binary data to send</param>
        /// <param name="dataOffset">offset in data to start sending</param>
        /// <param name="dataLength">number of bytes to send</param>
        /// <returns>Send status</returns>
        public SendStatus Send(byte[] data, int dataOffset, int dataLength)
        {
            if (ParentConnection.Root.ShuttingDown) { return (SendStatus.SEND_ON_CLOSED_SOCKET_ERROR); }

            IntPtr nData = Marshal.AllocHGlobal(dataLength);
            Marshal.Copy(data, dataOffset, nData, dataLength);
            SendStatus retVal = ILibWrapper_DLL_WebRTC_DataChannel_Send(ref nDataChannel, nData, dataLength);
            Marshal.FreeHGlobal(nData);
            return (retVal);
        }
        /// <summary>
        /// Send raw data
        /// </summary>
        /// <param name="data">Data to send</param>
        /// <param name="dataOffset">offset in data to start sending</param>
        /// <param name="dataLength">number of bytes to send</param>
        /// <param name="dataType">The type of data being sent</param>
        /// <returns>Send status</returns>
        public SendStatus Send(byte[] data, int dataOffset, int dataLength, int dataType)
        {
            if (ParentConnection.Root.ShuttingDown) { return (SendStatus.SEND_ON_CLOSED_SOCKET_ERROR); }

            IntPtr nData = Marshal.AllocHGlobal(dataLength);
            Marshal.Copy(data, 0, nData, dataLength);
            SendStatus retVal = ILibWrapper_DLL_WebRTC_DataChannel_SendEx(ref nDataChannel, nData, dataLength, dataType);
            Marshal.FreeHGlobal(nData);
            return (retVal);
        }
    }
    #endregion

    #region Fisher Yates Shuffle Extension
    public static class ListExtensionMethods
    {
        /// <summary>
        /// Shuffles a List, using the Fisher–Yates shuffle algorithm
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="list"></param>
        public static void Shuffle<T>(this IList<T> list)
        {
            Random rng = new Random();
            int n = list.Count;
            while (n > 1)
            {
                n--;
                int k = rng.Next(n + 1);
                T value = list[k];
                list[k] = list[n];
                list[n] = value;
            }
        }
    }
    #endregion
}
