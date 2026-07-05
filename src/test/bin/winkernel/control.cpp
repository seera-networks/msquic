/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Kernel Mode Test Driver

--*/

#include "quic_platform.h"
#include "MsQuicTests.h"
#include <new.h>

#include "quic_trace.h"
#ifdef QUIC_CLOG
#include "control.cpp.clog.h"
#endif

#include <ntdef.h>

#include "msquicp.h"

const MsQuicApi* MsQuic;
QUIC_CREDENTIAL_CONFIG ServerSelfSignedCredConfig;
QUIC_CREDENTIAL_CONFIG ServerSelfSignedCredConfigClientAuth;
QUIC_CREDENTIAL_CONFIG ClientCertCredConfig;
QUIC_CERTIFICATE_HASH SelfSignedCertHash;
QUIC_CERTIFICATE_HASH ClientCertHash;
bool UseDuoNic = false;

#ifdef PRIVATE_LIBRARY
DECLARE_CONST_UNICODE_STRING(QuicTestCtlDeviceName, L"\\Device\\" QUIC_DRIVER_NAME_PRIVATE);
DECLARE_CONST_UNICODE_STRING(QuicTestCtlDeviceSymLink, L"\\DosDevices\\" QUIC_DRIVER_NAME_PRIVATE);
#else
DECLARE_CONST_UNICODE_STRING(QuicTestCtlDeviceName, L"\\Device\\" QUIC_DRIVER_NAME);
DECLARE_CONST_UNICODE_STRING(QuicTestCtlDeviceSymLink, L"\\DosDevices\\" QUIC_DRIVER_NAME);
#endif

struct QUIC_DEVICE_EXTENSION {
    EX_PUSH_LOCK Lock;

    _Guarded_by_(Lock)
    LIST_ENTRY ClientList;
    ULONG ClientListSize;
};

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(QUIC_DEVICE_EXTENSION, QuicTestCtlGetDeviceContext);

struct QUIC_TEST_CLIENT {
    LIST_ENTRY Link;
    bool TestFailure;
};

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(QUIC_TEST_CLIENT, QuicTestCtlGetFileContext);

EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL QuicTestCtlEvtIoDeviceControl;
EVT_WDF_IO_QUEUE_IO_CANCELED_ON_QUEUE QuicTestCtlEvtIoCanceled;

PAGEDX EVT_WDF_DEVICE_FILE_CREATE QuicTestCtlEvtFileCreate;
PAGEDX EVT_WDF_FILE_CLOSE QuicTestCtlEvtFileClose;
PAGEDX EVT_WDF_FILE_CLEANUP QuicTestCtlEvtFileCleanup;

WDFDEVICE QuicTestCtlDevice = nullptr;
QUIC_DEVICE_EXTENSION* QuicTestCtlExtension = nullptr;
QUIC_TEST_CLIENT* QuicTestClient = nullptr;
HANDLE NmrClient = nullptr;

_No_competing_thread_
INITCODE
NTSTATUS
QuicTestCtlInitialize(
    _In_ WDFDRIVER Driver
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PWDFDEVICE_INIT DeviceInit = nullptr;
    WDF_FILEOBJECT_CONFIG FileConfig;
    WDF_OBJECT_ATTRIBUTES Attribs;
    WDFDEVICE Device;
    QUIC_DEVICE_EXTENSION* DeviceContext;
    WDF_IO_QUEUE_CONFIG QueueConfig;
    WDFQUEUE Queue;

#ifdef QUIC_TEST_NMR_PROVIDER
    QUIC_ENABLE_PRIVATE_NMR_PROVIDER();
#endif

    Status = MsQuicNmrClientRegister(&NmrClient, &MSQUIC_MODULE_ID, 5000);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "MsQuicNmrClientRegister failed");
        goto Error;
    }

    CXPLAT_DBG_ASSERT(
        NmrClient != nullptr && QUIC_GET_DISPATCH(NmrClient) != nullptr);

    MsQuic =
        new (std::nothrow) MsQuicApi(
            QUIC_GET_DISPATCH(NmrClient)->OpenVersion,
            QUIC_GET_DISPATCH(NmrClient)->Close);
    if (!MsQuic) {
        goto Error;
    }
    if (QUIC_FAILED(MsQuic->GetInitStatus())) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            MsQuic->GetInitStatus(),
            "MsQuicApi Constructor");
        goto Error;
    }

    DeviceInit =
        WdfControlDeviceInitAllocate(
            Driver,
            &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
    if (DeviceInit == nullptr) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "WdfControlDeviceInitAllocate failed");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Error;
    }

    Status =
        WdfDeviceInitAssignName(
            DeviceInit,
            &QuicTestCtlDeviceName);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WdfDeviceInitAssignName failed");
        goto Error;
    }

    WDF_FILEOBJECT_CONFIG_INIT(
        &FileConfig,
        QuicTestCtlEvtFileCreate,
        QuicTestCtlEvtFileClose,
        QuicTestCtlEvtFileCleanup);
    FileConfig.FileObjectClass = WdfFileObjectWdfCanUseFsContext2;

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&Attribs, QUIC_TEST_CLIENT);
    WdfDeviceInitSetFileObjectConfig(
        DeviceInit,
        &FileConfig,
        &Attribs);
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&Attribs, QUIC_DEVICE_EXTENSION);

    Status =
        WdfDeviceCreate(
            &DeviceInit,
            &Attribs,
            &Device);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WdfDeviceCreate failed");
        goto Error;
    }

    DeviceContext = QuicTestCtlGetDeviceContext(Device);
    RtlZeroMemory(DeviceContext, sizeof(QUIC_DEVICE_EXTENSION));
    ExInitializePushLock(&DeviceContext->Lock);
    InitializeListHead(&DeviceContext->ClientList);

    Status = WdfDeviceCreateSymbolicLink(Device, &QuicTestCtlDeviceSymLink);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WdfDeviceCreateSymbolicLink failed");
        goto Error;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&QueueConfig, WdfIoQueueDispatchParallel);
    QueueConfig.EvtIoDeviceControl = QuicTestCtlEvtIoDeviceControl;
    QueueConfig.EvtIoCanceledOnQueue = QuicTestCtlEvtIoCanceled;

    __analysis_assume(QueueConfig.EvtIoStop != 0);
    Status =
        WdfIoQueueCreate(
            Device,
            &QueueConfig,
            WDF_NO_OBJECT_ATTRIBUTES,
            &Queue);
    __analysis_assume(QueueConfig.EvtIoStop == 0);

    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WdfIoQueueCreate failed");
        goto Error;
    }

    QuicTestCtlDevice = Device;
    QuicTestCtlExtension = DeviceContext;

    WdfControlFinishInitializing(Device);

    QuicTraceLogVerbose(
        TestControlInitialized,
        "[test] Control interface initialized");

Error:

    if (DeviceInit) {
        WdfDeviceInitFree(DeviceInit);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
QuicTestCtlUninitialize(
    )
{
    QuicTraceLogVerbose(
        TestControlUninitializing,
        "[test] Control interface uninitializing");

    if (QuicTestCtlDevice != nullptr) {
        NT_ASSERT(QuicTestCtlExtension != nullptr);
        QuicTestCtlExtension = nullptr;

        WdfObjectDelete(QuicTestCtlDevice);
        QuicTestCtlDevice = nullptr;
    }

    delete MsQuic;

    if (NmrClient != nullptr) {
        MsQuicNmrClientDeregister(&NmrClient);
    }

    QuicTraceLogVerbose(
        TestControlUninitialized,
        "[test] Control interface uninitialized");
}

PAGEDX
_Use_decl_annotations_
VOID
QuicTestCtlEvtFileCreate(
    _In_ WDFDEVICE /* Device */,
    _In_ WDFREQUEST Request,
    _In_ WDFFILEOBJECT FileObject
    )
{
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    KeEnterGuardedRegion();
    ExAcquirePushLockExclusive(&QuicTestCtlExtension->Lock);

    do
    {
        if (QuicTestCtlExtension->ClientListSize >= 1) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "Already have max clients");
            Status = STATUS_TOO_MANY_SESSIONS;
            break;
        }

        QUIC_TEST_CLIENT* Client = QuicTestCtlGetFileContext(FileObject);
        if (Client == nullptr) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "nullptr File context in FileCreate");
            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        RtlZeroMemory(Client, sizeof(QUIC_TEST_CLIENT));

        //
        // Insert into the client list
        //
        InsertTailList(&QuicTestCtlExtension->ClientList, &Client->Link);
        QuicTestCtlExtension->ClientListSize++;

        QuicTraceLogInfo(
            TestControlClientCreated,
            "[test] Client %p created",
            Client);

        //
        // TODO: Add multiple device client support?
        //
        QuicTestClient = Client;
    }
    while (false);

    ExReleasePushLockExclusive(&QuicTestCtlExtension->Lock);
    KeLeaveGuardedRegion();

    WdfRequestComplete(Request, Status);
}

PAGEDX
_Use_decl_annotations_
VOID
QuicTestCtlEvtFileClose(
    _In_ WDFFILEOBJECT /* FileObject */
    )
{
    PAGED_CODE();
}

PAGEDX
_Use_decl_annotations_
VOID
QuicTestCtlEvtFileCleanup(
    _In_ WDFFILEOBJECT FileObject
    )
{
    PAGED_CODE();

    KeEnterGuardedRegion();

    QUIC_TEST_CLIENT* Client = QuicTestCtlGetFileContext(FileObject);
    if (Client != nullptr) {

        ExAcquirePushLockExclusive(&QuicTestCtlExtension->Lock);

        //
        // Remove the device client from the list
        //
        RemoveEntryList(&Client->Link);
        QuicTestCtlExtension->ClientListSize--;

        ExReleasePushLockExclusive(&QuicTestCtlExtension->Lock);

        QuicTraceLogInfo(
            TestControlClientCleaningUp,
            "[test] Client %p cleaning up",
            Client);

        ServerSelfSignedCredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
        QuicTestClient = nullptr;
    }

    KeLeaveGuardedRegion();
}

VOID
QuicTestCtlEvtIoCanceled(
    _In_ WDFQUEUE /* Queue */,
    _In_ WDFREQUEST Request
    )
{
    NTSTATUS Status;

    WDFFILEOBJECT FileObject = WdfRequestGetFileObject(Request);
    if (FileObject == nullptr) {
        Status = STATUS_DEVICE_NOT_READY;
        goto error;
    }

    QUIC_TEST_CLIENT* Client = QuicTestCtlGetFileContext(FileObject);
    if (Client == nullptr) {
        Status = STATUS_DEVICE_NOT_READY;
        goto error;
    }

    QuicTraceLogWarning(
        TestControlClientCanceledRequest,
        "[test] Client %p canceled request %p",
        Client,
        Request);

    Status = STATUS_CANCELLED;

error:

    WdfRequestComplete(Request, Status);
}

// Base template providing a readable error for unsupported scenarios
template<class... Args>
QUIC_STATUS InvokeTestFunction(void(Args...), const uint8_t*, uint32_t) {
    static_assert(false, "Only functions with no argument or one constant reference argument are supported");
}

// Specialization for functions with one const reference argument
template<class Arg>
QUIC_STATUS InvokeTestFunction(void(*func)(const Arg&), const uint8_t* argBuffer, uint32_t argBufferSize) {
    if (sizeof(Arg) != argBufferSize) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Invalid parameter size for test function");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    const Arg& arg = *reinterpret_cast<const Arg*>(argBuffer);
    func(arg);
    return QUIC_STATUS_SUCCESS;
}

// Specialization for functions with no arguments
template<>
QUIC_STATUS InvokeTestFunction(void(*func)(), const uint8_t*, uint32_t argBufferSize) {
    if (0 != argBufferSize) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Parameter provided for a test function expecting none");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    func();
    return QUIC_STATUS_SUCCESS;
}

#define RegisterTestFunction(Function) \
    do { \
        if (strcmp(Request->FunctionName, #Function) == 0) { \
            return InvokeTestFunction( \
                Function, \
                (const uint8_t*)(Request + 1), \
                Request->ParameterSize); \
        } \
    } while (false)

QUIC_STATUS
ExecuteTestRequest(
    _In_ QUIC_RUN_TEST_REQUEST* Request
    )
{
    sizeof(QUIC_TEST_CONFIGURATION_PARAMS),
    sizeof(QUIC_RUN_CERTIFICATE_PARAMS),
    0,
    0,
    0,
    0,
    sizeof(UINT8),
    0,
    0,
    sizeof(INT32),
    0,
    0,
    sizeof(INT32),
    0,
    sizeof(INT32),
    sizeof(INT32),
    sizeof(QUIC_RUN_CONNECT_PARAMS),
    sizeof(QUIC_RUN_CONNECT_AND_PING_PARAMS),
    sizeof(UINT8),
    sizeof(QUIC_CERTIFICATE_HASH_STORE),
    sizeof(INT32),
    sizeof(INT32),
    sizeof(INT32),
    0,
    sizeof(UINT8),
    sizeof(uint32_t),
    sizeof(uint32_t),
    sizeof(INT32),
    sizeof(QUIC_RUN_KEY_UPDATE_PARAMS),
    0,
    sizeof(INT32),
    sizeof(QUIC_RUN_ABORTIVE_SHUTDOWN_PARAMS),
    sizeof(QUIC_RUN_CID_UPDATE_PARAMS),
    sizeof(QUIC_RUN_RECEIVE_RESUME_PARAMS),
    sizeof(QUIC_RUN_RECEIVE_RESUME_PARAMS),
    0,
    sizeof(QUIC_RUN_DRILL_INITIAL_PACKET_CID_PARAMS),
    sizeof(INT32),
    0,
    sizeof(QUIC_RUN_DATAGRAM_NEGOTIATION),
    sizeof(INT32),
    sizeof(QUIC_RUN_REBIND_PARAMS),
    sizeof(QUIC_RUN_REBIND_PARAMS),
    sizeof(INT32),
    sizeof(INT32),
    0,
    sizeof(INT32),
    sizeof(QUIC_RUN_CUSTOM_CERT_VALIDATION),
    sizeof(INT32),
    sizeof(INT32),
    sizeof(QUIC_RUN_VERSION_NEGOTIATION_EXT),
    sizeof(QUIC_RUN_VERSION_NEGOTIATION_EXT),
    sizeof(QUIC_RUN_VERSION_NEGOTIATION_EXT),
    sizeof(INT32),
    sizeof(INT32),
    0,
    sizeof(QUIC_RUN_CONNECT_CLIENT_CERT),
    0,
    0,
    sizeof(QUIC_RUN_CRED_VALIDATION),
    sizeof(QUIC_RUN_CRED_VALIDATION),
    sizeof(QUIC_RUN_CRED_VALIDATION),
    sizeof(QUIC_RUN_CRED_VALIDATION),
    sizeof(QUIC_ABORT_RECEIVE_TYPE),
    sizeof(QUIC_RUN_KEY_UPDATE_RANDOM_LOSS_PARAMS),
    0,
    0,
    0,
    sizeof(QUIC_RUN_MTU_DISCOVERY_PARAMS),
    sizeof(INT32),
    sizeof(INT32),
    0,
    0,
    sizeof(INT32),
    0,
    sizeof(UINT8),
    sizeof(INT32),
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    sizeof(QUIC_RUN_CRED_VALIDATION),
    sizeof(QUIC_RUN_CIBIR_EXTENSION),
    0,
    0,
    sizeof(INT32),
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    sizeof(QUIC_RUN_VN_TP_ODD_SIZE_PARAMS),
    sizeof(UINT8),
    sizeof(UINT8),
    sizeof(UINT8),
    sizeof(BOOLEAN),
    sizeof(INT32),
    sizeof(QUIC_HANDSHAKE_LOSS_PARAMS),
    sizeof(QUIC_RUN_CUSTOM_CERT_VALIDATION),
    sizeof(QUIC_RUN_FEATURE_NEGOTIATION),
    sizeof(QUIC_RUN_FEATURE_NEGOTIATION),
    0,
    0,
    0,
    sizeof(INT32),
    0,
    sizeof(QUIC_RUN_CANCEL_ON_LOSS_PARAMS),
    sizeof(uint32_t),
    sizeof(QUIC_RUN_PROBE_PATH_PARAMS),
    sizeof(QUIC_RUN_MIGRATION_PARAMS),
};

    // Register any test functions here
    RegisterTestFunction(QuicTestValidateApi);
    RegisterTestFunction(QuicTestValidateRegistration);
    RegisterTestFunction(QuicTestGlobalParam);
    RegisterTestFunction(QuicTestCommonParam);
    RegisterTestFunction(QuicTestRegistrationParam);
    RegisterTestFunction(QuicTestConfigurationParam);
    RegisterTestFunction(QuicTestListenerParam);
    RegisterTestFunction(QuicTestConnectionParam);
    RegisterTestFunction(QuicTestTlsParam);
    RegisterTestFunction(QuicTestTlsHandshakeInfo);
    RegisterTestFunction(QuicTestStreamParam);
    RegisterTestFunction(QuicTestGetPerfCounters);
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestValidateEncryptDecryptPerfCounters);
    RegisterTestFunction(QuicTestConnQueueDelayStatistics);
#endif
    RegisterTestFunction(QuicTestValidateConfiguration);
    RegisterTestFunction(QuicTestValidateListener);
    RegisterTestFunction(QuicTestValidateConnection);
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestValidateConnectionPoolCreate);
    RegisterTestFunction(QuicTestValidateExecutionContext);
    RegisterTestFunction(QuicTestValidatePartition);
#endif // QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestRegistrationShutdownBeforeConnOpen);
    RegisterTestFunction(QuicTestRegistrationShutdownAfterConnOpen);
    RegisterTestFunction(QuicTestRegistrationShutdownAfterConnOpenBeforeStart);
    RegisterTestFunction(QuicTestRegistrationShutdownAfterConnOpenAndStart);
    RegisterTestFunction(QuicTestConnectionCloseBeforeStreamClose);
    RegisterTestFunction(QuicTestValidateStream);
    RegisterTestFunction(QuicTestCloseConnBeforeStreamFlush);
    RegisterTestFunction(QuicTestValidateConnectionEvents);
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestValidateNetStatsConnEvent);
#endif
    RegisterTestFunction(QuicTestValidateStreamEvents);
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestVersionSettings);
#endif
    RegisterTestFunction(QuicTestValidateParamApi);
    RegisterTestFunction(QuicTestCredentialLoad);
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestRegistrationOpenClose);
#endif
    RegisterTestFunction(QuicTestCreateListener);
    RegisterTestFunction(QuicTestStartListener);
    RegisterTestFunction(QuicTestStartListenerMultiAlpns);
    RegisterTestFunction(QuicTestStartListenerImplicit);
    RegisterTestFunction(QuicTestStartTwoListeners);
    RegisterTestFunction(QuicTestStartTwoListenersSameALPN);
    RegisterTestFunction(QuicTestStartListenerExplicit);
    RegisterTestFunction(QuicTestCreateConnection);
    RegisterTestFunction(QuicTestConnectionCloseFromCallback);
    RegisterTestFunction(QuicTestConnectionRejection);
#ifdef QUIC_TEST_DATAPATH_HOOKS_ENABLED
    RegisterTestFunction(QuicTestEcn);
    RegisterTestFunction(QuicTestLocalPathChanges);
    RegisterTestFunction(QuicTestMtuSettings);
    RegisterTestFunction(QuicTestMtuDiscovery);
#endif // QUIC_TEST_DATAPATH_HOOKS_ENABLED
    RegisterTestFunction(QuicTestValidAlpnLengths);
    RegisterTestFunction(QuicTestInvalidAlpnLengths);
    RegisterTestFunction(QuicTestChangeAlpn);
    RegisterTestFunction(QuicTestBindConnectionImplicit);
    RegisterTestFunction(QuicTestBindConnectionExplicit);
    RegisterTestFunction(QuicTestAddrFunctions);
    RegisterTestFunction(QuicTestConnect_Connect);
#ifndef QUIC_DISABLE_RESUMPTION
    RegisterTestFunction(QuicTestConnect_Resume);
    RegisterTestFunction(QuicTestConnect_ResumeAsync);
    RegisterTestFunction(QuicTestConnect_ResumeRejection);
    RegisterTestFunction(QuicTestConnect_ResumeRejectionByServerApp);
    RegisterTestFunction(QuicTestConnect_ResumeRejectionByServerAppAsync);
#endif // QUIC_DISABLE_RESUMPTION
#ifndef QUIC_DISABLE_SHARED_PORT_TESTS
    RegisterTestFunction(QuicTestClientSharedLocalPort);
#endif
    RegisterTestFunction(QuicTestInterfaceBinding);
    RegisterTestFunction(QuicTestRetryMemoryLimitConnect);
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestConnect_OldVersion);
#endif
    RegisterTestFunction(QuicTestConnect_AsyncSecurityConfig);
    RegisterTestFunction(QuicTestConnect_AsyncSecurityConfig_Delayed);
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestVersionNegotiation);
    RegisterTestFunction(QuicTestVersionNegotiationRetry);
    RegisterTestFunction(QuicTestCompatibleVersionNegotiationRetry);
    RegisterTestFunction(QuicTestCompatibleVersionNegotiation);
    RegisterTestFunction(QuicTestCompatibleVersionNegotiationDefaultServer);
    RegisterTestFunction(QuicTestCompatibleVersionNegotiationDefaultClient);
    RegisterTestFunction(QuicTestIncompatibleVersionNegotiation);
    RegisterTestFunction(QuicTestFailedVersionNegotiation);
    RegisterTestFunction(QuicTestReliableResetNegotiation);
    RegisterTestFunction(QuicTestOneWayDelayNegotiation);
#endif // QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestCustomServerCertificateValidation);
    RegisterTestFunction(QuicTestCustomClientCertificateValidation);
    RegisterTestFunction(QuicTestCustomServerCertValidationAfterShutdown);
    RegisterTestFunction(QuicTestCustomClientCertValidationAfterShutdown);
    RegisterTestFunction(QuicTestConnectClientCertificate);
    RegisterTestFunction(QuicTestCibirExtension);
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
#if QUIC_TEST_DISABLE_VNE_TP_GENERATION
    RegisterTestFunction(QuicTestVNTPOddSize);
    RegisterTestFunction(QuicTestVNTPChosenVersionMismatch);
    RegisterTestFunction(QuicTestVNTPChosenVersionZero);
    RegisterTestFunction(QuicTestVNTPOtherVersionZero);
#endif
#endif
#if QUIC_TEST_FAILING_TEST_CERTIFICATES
    RegisterTestFunction(QuicTestConnectExpiredServerCertificate);
    RegisterTestFunction(QuicTestConnectValidServerCertificate);
    RegisterTestFunction(QuicTestConnectValidClientCertificate);
    RegisterTestFunction(QuicTestConnectExpiredClientCertificate);
#endif
    RegisterTestFunction(QuicTestConnectUnreachable);
    RegisterTestFunction(QuicTestConnectInvalidAddress);
    RegisterTestFunction(QuicTestConnectBadAlpn);
    RegisterTestFunction(QuicTestConnectBadSni);
    RegisterTestFunction(QuicTestConnectIpSni);
    RegisterTestFunction(QuicTestConnectServerRejected);
    RegisterTestFunction(QuicTestClientBlockedSourcePort);
#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
    RegisterTestFunction(QuicTestPathValidationTimeout);
    RegisterTestFunction(QuicTestPathValidationLastPathClose);
    RegisterTestFunction(QuicTestNatPortRebind_NoPadding);
    RegisterTestFunction(QuicTestNatPortRebind_WithPadding);
    RegisterTestFunction(QuicTestNatAddrRebind_NoPadding);
    RegisterTestFunction(QuicTestNatAddrRebind_WithPadding);
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestProbePath_NoShareBinding);
    RegisterTestFunction(QuicTestProbePath_WithShareBinding);
    RegisterTestFunction(QuicTestProbePathFailed_NoShareBinding);
    RegisterTestFunction(QuicTestProbePathFailed_WithShareBinding);
    RegisterTestFunction(QuicTestAddPathBeforeStart_NoShareBinding);
    RegisterTestFunction(QuicTestAddPathBeforeStart_WithShareBinding);
    RegisterTestFunction(QuicTestMigration_NoShareBinding);
    RegisterTestFunction(QuicTestMigration_WithShareBinding);
    RegisterTestFunction(QuicTestAddressDiscovery);
    RegisterTestFunction(QuicTestServerProbePath);
    RegisterTestFunction(QuicTestServerMigration);
#endif // QUIC_API_ENABLE_PREVIEW_FEATURES
#endif // QUIC_TEST_DATAPATH_HOOKS_ENABLED
    RegisterTestFunction(QuicTestChangeMaxStreamID);
#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
    RegisterTestFunction(QuicTestLoadBalancedHandshake);
    RegisterTestFunction(QuicCancelOnLossSend);
    RegisterTestFunction(QuicTestConnect_RandomLoss);
#ifndef QUIC_DISABLE_RESUMPTION
    RegisterTestFunction(QuicTestConnect_RandomLossResume);
    RegisterTestFunction(QuicTestConnect_RandomLossResumeRejection);
#endif // QUIC_DISABLE_RESUMPTION
    RegisterTestFunction(QuicTestHandshakeSpecificLossPatterns);
#endif // QUIC_TEST_DATAPATH_HOOKS_ENABLED
    RegisterTestFunction(QuicTestShutdownDuringHandshake);
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestConnectionPoolCreate);
#endif // QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestConnectAndIdle);
    RegisterTestFunction(QuicTestConnectAndIdleForDestCidChange);
    RegisterTestFunction(QuicTestServerDisconnect);
    RegisterTestFunction(QuicTestClientDisconnect);
    RegisterTestFunction(QuicAbortiveTransfers);
    RegisterTestFunction(QuicTestStatelessResetKey);
    RegisterTestFunction(QuicTestForceKeyUpdate);
    RegisterTestFunction(QuicTestKeyUpdate);
#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
    RegisterTestFunction(QuicTestKeyUpdateRandomLoss);
#endif // QUIC_TEST_DATAPATH_HOOKS_ENABLED
    RegisterTestFunction(QuicTestCidUpdate);
    RegisterTestFunction(QuicTestAckSendDelay);
    RegisterTestFunction(QuicTestReceiveResume);
    RegisterTestFunction(QuicTestReceiveResumeNoData);
    RegisterTestFunction(QuicTestAbortReceive_Paused);
    RegisterTestFunction(QuicTestAbortReceive_Pending);
    RegisterTestFunction(QuicTestAbortReceive_Incomplete);
    RegisterTestFunction(QuicTestSlowReceive);
#ifndef QUIC_DISABLE_0RTT_TESTS
    RegisterTestFunction(QuicTestConnectAndPing_Send0Rtt);
    RegisterTestFunction(QuicTestConnectAndPing_Reject0Rtt);
    RegisterTestFunction(QuicTestCustomTicketValidationAfterShutdown);
#endif // QUIC_DISABLE_0RTT_TESTS
    RegisterTestFunction(QuicTestConnectAndPing_SendLarge);
    RegisterTestFunction(QuicTestConnectAndPing_SendIntermittently);
    RegisterTestFunction(QuicTestConnectAndPing_Send);
#ifdef QUIC_TEST_ALLOC_FAILURES_ENABLED
#ifndef QUIC_TEST_OPENSSL_FLAGS // Not supported on OpenSSL
    RegisterTestFunction(QuicTestNthAllocFail);
#endif // QUIC_TEST_OPENSSL_FLAGS
#endif // QUIC_TEST_ALLOC_FAILURES_ENABLED
#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
    RegisterTestFunction(QuicTestNthPacketDrop);
#endif // QUIC_TEST_DATAPATH_HOOKS_ENABLED
    RegisterTestFunction(QuicTestStreamPriority);
    RegisterTestFunction(QuicTestStreamPriorityInfiniteLoop);
    RegisterTestFunction(QuicTestStreamDifferentAbortErrors);
    RegisterTestFunction(QuicTestStreamAbortRecvFinRace);
#ifdef QUIC_PARAM_STREAM_RELIABLE_OFFSET
    RegisterTestFunction(QuicTestStreamReliableReset);
    RegisterTestFunction(QuicTestStreamReliableResetMultipleSends);
#endif // QUIC_PARAM_STREAM_RELIABLE_OFFSET
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestStreamMultiReceive);
    RegisterTestFunction(QuicTestStreamAppProvidedBuffers_ClientSend);
    RegisterTestFunction(QuicTestStreamAppProvidedBuffers_ServerSend);
    RegisterTestFunction(QuicTestStreamAppProvidedBuffersOutOfSpace_ClientSend_AbortStream);
    RegisterTestFunction(QuicTestStreamAppProvidedBuffersOutOfSpace_ClientSend_ProvideMoreBuffer);
    RegisterTestFunction(QuicTestStreamAppProvidedBuffersOutOfSpace_ServerSend_AbortStream);
    RegisterTestFunction(QuicTestStreamAppProvidedBuffersOutOfSpace_ServerSend_ProvideMoreBuffer);
#endif // QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestStreamBlockUnblockConnFlowControl_Bidi);
    RegisterTestFunction(QuicTestStreamBlockUnblockConnFlowControl_Unidi);
    RegisterTestFunction(QuicTestStreamAbortConnFlowControl);
    RegisterTestFunction(QuicTestOperationPriority);
    RegisterTestFunction(QuicTestConnectionPriority);
    RegisterTestFunction(QuicDrillTestVarIntEncoder);
    RegisterTestFunction(QuicDrillTestInitialCid);
    RegisterTestFunction(QuicDrillTestInitialToken);
    RegisterTestFunction(QuicDrillTestServerVNPacket);
    RegisterTestFunction(QuicDrillTestKeyUpdateDuringHandshake);
    RegisterTestFunction(QuicTestDatagramNegotiation);
    RegisterTestFunction(QuicTestDatagramSend);
    RegisterTestFunction(QuicTestDatagramDrop);
    RegisterTestFunction(QuicTestStorage);
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestVersionStorage);
#endif // QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestRetryConfigSetting);

typedef union {
    QUIC_TEST_CONFIGURATION_PARAMS TestConfigurationParams;
    QUIC_RUN_CERTIFICATE_PARAMS CertParams;
    QUIC_CERTIFICATE_HASH_STORE CertHashStore;
    UINT8 Connect;
    INT32 Family;
    QUIC_RUN_CONNECT_PARAMS Params1;
    QUIC_RUN_CONNECT_AND_PING_PARAMS Params2;
    QUIC_RUN_KEY_UPDATE_PARAMS Params3;
    QUIC_RUN_ABORTIVE_SHUTDOWN_PARAMS Params4;
    QUIC_RUN_CID_UPDATE_PARAMS Params5;
    QUIC_RUN_RECEIVE_RESUME_PARAMS Params6;
    QUIC_RUN_CANCEL_ON_LOSS_PARAMS Params7;
    UINT8 EnableKeepAlive;
    UINT8 StopListenerFirst;
    QUIC_RUN_DRILL_INITIAL_PACKET_CID_PARAMS DrillParams;
    QUIC_RUN_DATAGRAM_NEGOTIATION DatagramNegotiationParams;
    QUIC_RUN_CUSTOM_CERT_VALIDATION CustomCertValidationParams;
    QUIC_RUN_VERSION_NEGOTIATION_EXT VersionNegotiationExtParams;
    QUIC_RUN_CONNECT_CLIENT_CERT ConnectClientCertParams;
    QUIC_RUN_CRED_VALIDATION CredValidationParams;
    QUIC_ABORT_RECEIVE_TYPE AbortReceiveType;
    QUIC_RUN_KEY_UPDATE_RANDOM_LOSS_PARAMS KeyUpdateRandomLossParams;
    QUIC_RUN_MTU_DISCOVERY_PARAMS MtuDiscoveryParams;
    uint32_t Test;
    QUIC_RUN_PROBE_PATH_PARAMS ProbePathParams;
    QUIC_RUN_MIGRATION_PARAMS MigrationParams;
    QUIC_RUN_REBIND_PARAMS RebindParams;
    UINT8 RejectByClosing;
    QUIC_RUN_CIBIR_EXTENSION CibirParams;
    QUIC_RUN_VN_TP_ODD_SIZE_PARAMS OddSizeVnTpParams;
    UINT8 TestServerVNTP;
    BOOLEAN Bidirectional;
    QUIC_RUN_FEATURE_NEGOTIATION FeatureNegotiationParams;
    QUIC_HANDSHAKE_LOSS_PARAMS HandshakeLossParams;
} QUIC_IOCTL_PARAMS;

    QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.", Buffer);

    return QUIC_STATUS_NOT_SUPPORTED;
}

VOID
QuicTestCtlEvtIoDeviceControl(
    _In_ WDFQUEUE /* Queue */,
    _In_ WDFREQUEST Request,
    _In_ size_t /* OutputBufferLength */,
    _In_ size_t /* InputBufferLength */,
    _In_ ULONG IoControlCode
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    WDFFILEOBJECT FileObject = nullptr;
    QUIC_TEST_CLIENT* Client = nullptr;

    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        Status = STATUS_NOT_SUPPORTED;
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "IOCTL not supported greater than PASSIVE_LEVEL");
        goto Error;
    }

    FileObject = WdfRequestGetFileObject(Request);
    if (FileObject == nullptr) {
        Status = STATUS_DEVICE_NOT_READY;
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "WdfRequestGetFileObject failed");
        goto Error;
    }

    Client = QuicTestCtlGetFileContext(FileObject);
    if (Client == nullptr) {
        Status = STATUS_DEVICE_NOT_READY;
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "QuicTestCtlGetFileContext failed");
        goto Error;
    }

    const ULONG FunctionCode = IoGetFunctionCodeFromCtlCode(IoControlCode);

    QuicTraceLogInfo(
        TestControlClientIoctl,
        "[test] Client %p executing IOCTL %u",
        Client,
        FunctionCode);

    // Validate the security config is set first.
    if (IoControlCode != IOCTL_QUIC_SET_CERT_PARAMS &&
        ServerSelfSignedCredConfig.Type == QUIC_CREDENTIAL_TYPE_NONE) {
        Status = STATUS_INVALID_DEVICE_STATE;
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Client didn't set Security Config");
        goto Error;
    }

    switch (IoControlCode) {

    case IOCTL_QUIC_TEST_CONFIGURATION:
    {
        QUIC_TEST_CONFIGURATION_PARAMS* TestConfig{};
        Status =
            WdfRequestRetrieveInputBuffer(
                Request, sizeof(*TestConfig), reinterpret_cast<void**>(&TestConfig), nullptr);

        if (!NT_SUCCESS(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "WdfRequestRetrieveInputBuffer failed for IOCTL_QUIC_TEST_CONFIGURATION");
            break;
        }

        UseDuoNic = TestConfig->UseDuoNic;
        RtlCopyMemory(CurrentWorkingDirectory, "\\DosDevices\\", sizeof("\\DosDevices\\"));
        Status =
            RtlStringCbCatExA(
                CurrentWorkingDirectory,
                sizeof(CurrentWorkingDirectory),
                TestConfig->CurrentDirectory,
                nullptr,
                nullptr,
                STRSAFE_NULL_ON_FAILURE);

        //
        // We don't want to hinge the result of 'Status = ' on this setparam call because
        // this SetParam will only succeed the first time, before the datapath initializes.
        // User mode tests already ensure at most 1 setparam call. But in Kernel mode, this IOCTL
        // can be invoked many times.
        // If the datapath is already initialized, this setparam call should fail silently.
        //
        BOOLEAN EnableDscpRecvOption = TRUE;
        MsQuic->SetParam(
                nullptr,
                QUIC_PARAM_GLOBAL_DATAPATH_DSCP_RECV_ENABLED,
                sizeof(BOOLEAN),
                &EnableDscpRecvOption);
        break;
    }
    case IOCTL_QUIC_SET_CERT_PARAMS:
    {
        QUIC_RUN_CERTIFICATE_PARAMS* CertParams{};
        Status =
            WdfRequestRetrieveInputBuffer(
                Request, sizeof(*CertParams), reinterpret_cast<void**>(&CertParams), nullptr);

        if (!NT_SUCCESS(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "WdfRequestRetrieveInputBuffer failed for IOCTL_QUIC_SET_CERT_PARAMS");
            break;
        }

        ServerSelfSignedCredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
        ServerSelfSignedCredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;
        ServerSelfSignedCredConfig.CertificateHash = &SelfSignedCertHash;
        ServerSelfSignedCredConfigClientAuth.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
        ServerSelfSignedCredConfigClientAuth.Flags =
            QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION |
            QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION |
            QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
        ServerSelfSignedCredConfigClientAuth.CertificateHash = &SelfSignedCertHash;
        RtlCopyMemory(&SelfSignedCertHash.ShaHash, &CertParams->ServerCertHash, sizeof(QUIC_CERTIFICATE_HASH));
        ClientCertCredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
        ClientCertCredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
        ClientCertCredConfig.CertificateHash = &ClientCertHash;
        RtlCopyMemory(&ClientCertHash.ShaHash, &CertParams->ClientCertHash, sizeof(QUIC_CERTIFICATE_HASH));

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case IOCTL_QUIC_RUN_VALIDATE_REGISTRATION:
        QuicTestCtlRun(QuicTestValidateRegistration());
        break;
    case IOCTL_QUIC_RUN_VALIDATE_CONFIGURATION:
        QuicTestCtlRun(QuicTestValidateConfiguration());
        break;
    case IOCTL_QUIC_RUN_VALIDATE_LISTENER:
        QuicTestCtlRun(QuicTestValidateListener());
        break;
    case IOCTL_QUIC_RUN_VALIDATE_CONNECTION:
        QuicTestCtlRun(QuicTestValidateConnection());
        break;
    case IOCTL_QUIC_RUN_VALIDATE_STREAM:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestValidateStream(Params->Connect != 0));
        break;

    case IOCTL_QUIC_RUN_CREATE_LISTENER:
        QuicTestCtlRun(QuicTestCreateListener());
        break;
    case IOCTL_QUIC_RUN_START_LISTENER:
        QuicTestCtlRun(QuicTestStartListener());
        break;
    case IOCTL_QUIC_RUN_START_LISTENER_IMPLICIT:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestStartListenerImplicit(Params->Family));
        break;
    case IOCTL_QUIC_RUN_START_TWO_LISTENERS:
        QuicTestCtlRun(QuicTestStartTwoListeners());
        break;
    case IOCTL_QUIC_RUN_START_TWO_LISTENERS_SAME_ALPN:
        QuicTestCtlRun(QuicTestStartTwoListenersSameALPN());
        break;
    case IOCTL_QUIC_RUN_START_LISTENER_EXPLICIT:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestStartListenerExplicit(Params->Family));
        break;
    case IOCTL_QUIC_RUN_CREATE_CONNECTION:
        QuicTestCtlRun(QuicTestCreateConnection());
        break;
    case IOCTL_QUIC_RUN_BIND_CONNECTION_IMPLICIT:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestBindConnectionImplicit(Params->Family));
        break;
    case IOCTL_QUIC_RUN_BIND_CONNECTION_EXPLICIT:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestBindConnectionExplicit(Params->Family));
        break;

    case IOCTL_QUIC_RUN_CONNECT:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestConnect(
                Params->Params1.Family,
                Params->Params1.ServerStatelessRetry != 0,
                Params->Params1.ClientUsesOldVersion != 0,
                Params->Params1.MultipleALPNs != 0,
                Params->Params1.GreaseQuicBitExtension != 0,
                (QUIC_TEST_ASYNC_CONFIG_MODE)Params->Params1.AsyncConfiguration,
                Params->Params1.MultiPacketClientInitial != 0,
                (QUIC_TEST_RESUMPTION_MODE)Params->Params1.SessionResumption,
                Params->Params1.RandomLossPercentage
                ));
        break;

    case IOCTL_QUIC_RUN_CONNECT_AND_PING:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestConnectAndPing(
                Params->Params2.Family,
                Params->Params2.Length,
                Params->Params2.ConnectionCount,
                Params->Params2.StreamCount,
                Params->Params2.StreamBurstCount,
                Params->Params2.StreamBurstDelayMs,
                Params->Params2.ServerStatelessRetry != 0,
                Params->Params2.ClientRebind != 0,
                Params->Params2.ClientZeroRtt != 0,
                Params->Params2.ServerRejectZeroRtt != 0,
                Params->Params2.UseSendBuffer != 0,
                Params->Params2.UnidirectionalStreams != 0,
                Params->Params2.ServerInitiatedStreams != 0,
                Params->Params2.FifoScheduling != 0
                ));
        break;

    case IOCTL_QUIC_RUN_CONNECT_AND_IDLE:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestConnectAndIdle(Params->EnableKeepAlive != 0));
        break;

    case IOCTL_QUIC_RUN_CONNECT_UNREACHABLE:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestConnectUnreachable(Params->Family));
        break;

    case IOCTL_QUIC_RUN_CONNECT_BAD_ALPN:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestConnectBadAlpn(Params->Family));
        break;

    case IOCTL_QUIC_RUN_CONNECT_BAD_SNI:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestConnectBadSni(Params->Family));
        break;

    case IOCTL_QUIC_RUN_SERVER_DISCONNECT:
        QuicTestCtlRun(QuicTestServerDisconnect());
        break;

    case IOCTL_QUIC_RUN_CLIENT_DISCONNECT:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestClientDisconnect(Params->StopListenerFirst));
        break;

    case IOCTL_QUIC_RUN_VALIDATE_CONNECTION_EVENTS:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestValidateConnectionEvents(Params->Test));
        break;

    case IOCTL_QUIC_RUN_VALIDATE_STREAM_EVENTS:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestValidateStreamEvents(Params->Test));
        break;

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    case IOCTL_QUIC_RUN_VERSION_NEGOTIATION:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestVersionNegotiation(Params->Family));
        break;
#endif

    case IOCTL_QUIC_RUN_KEY_UPDATE:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestKeyUpdate(
                Params->Params3.Family,
                Params->Params3.Iterations,
                Params->Params3.KeyUpdateBytes,
                Params->Params3.UseKeyUpdateBytes != 0,
                Params->Params3.ClientKeyUpdate != 0,
                Params->Params3.ServerKeyUpdate != 0));
        break;

    case IOCTL_QUIC_RUN_VALIDATE_API:
        QuicTestCtlRun(QuicTestValidateApi());
        break;

    case IOCTL_QUIC_RUN_CONNECT_SERVER_REJECTED:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestConnectServerRejected(Params->Family));
        break;

    case IOCTL_QUIC_RUN_ABORTIVE_SHUTDOWN:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicAbortiveTransfers(
                Params->Params4.Family,
                Params->Params4.Flags));
        break;

    case IOCTL_QUIC_RUN_CID_UPDATE:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestCidUpdate(
                Params->Params5.Family,
                Params->Params5.Iterations));
        break;

    case IOCTL_QUIC_RUN_RECEIVE_RESUME:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestReceiveResume(
                Params->Params6.Family,
                Params->Params6.SendBytes,
                Params->Params6.ConsumeBytes,
                Params->Params6.ShutdownType,
                Params->Params6.PauseType,
                Params->Params6.PauseFirst));
        break;

    case IOCTL_QUIC_RUN_RECEIVE_RESUME_NO_DATA:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestReceiveResumeNoData(
                Params->Params6.Family,
                Params->Params6.ShutdownType));
        break;

    case IOCTL_QUIC_RUN_DRILL_ENCODE_VAR_INT:
        QuicTestCtlRun(
            QuicDrillTestVarIntEncoder());
        break;

    case IOCTL_QUIC_RUN_DRILL_INITIAL_PACKET_CID:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicDrillTestInitialCid(
                Params->DrillParams.Family,
                Params->DrillParams.SourceOrDest,
                Params->DrillParams.ActualCidLengthValid,
                Params->DrillParams.ShortCidLength,
                Params->DrillParams.CidLengthFieldValid));
        break;

    case IOCTL_QUIC_RUN_DRILL_INITIAL_PACKET_TOKEN:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicDrillTestInitialToken(
                Params->Family));
        break;

    case IOCTL_QUIC_RUN_START_LISTENER_MULTI_ALPN:
        QuicTestCtlRun(QuicTestStartListenerMultiAlpns());
        break;

    case IOCTL_QUIC_RUN_DATAGRAM_NEGOTIATION:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestDatagramNegotiation(
                Params->DatagramNegotiationParams.Family,
                Params->DatagramNegotiationParams.DatagramReceiveEnabled));
        break;

    case IOCTL_QUIC_RUN_DATAGRAM_SEND:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestDatagramSend(
                Params->Family));
        break;

    case IOCTL_QUIC_RUN_PROBE_PATH:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestProbePath(
                Params->ProbePathParams.Family,
                Params->ProbePathParams.ShareBinding,
                Params->ProbePathParams.DeferConnIDGen,
                Params->ProbePathParams.DropPacketCount));
        break;

    case IOCTL_QUIC_RUN_MIGRATION:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestMigration(
                Params->MigrationParams.Family,
                Params->MigrationParams.ShareBinding,
                Params->MigrationParams.Smooth));
        break;

    case IOCTL_QUIC_RUN_NAT_PORT_REBIND:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestNatPortRebind(
                Params->RebindParams.Family,
                Params->RebindParams.Padding));
        break;

    case IOCTL_QUIC_RUN_NAT_ADDR_REBIND:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestNatAddrRebind(
                Params->RebindParams.Family,
                Params->RebindParams.Padding,
                FALSE));
        break;

    case IOCTL_QUIC_RUN_CHANGE_MAX_STREAM_ID:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestChangeMaxStreamID(
                Params->Family));
        break;

    case IOCTL_QUIC_RUN_PATH_VALIDATION_TIMEOUT:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestPathValidationTimeout(
                Params->Family));
        break;

    case IOCTL_QUIC_RUN_VALIDATE_GET_PERF_COUNTERS:
        QuicTestCtlRun(QuicTestGetPerfCounters());
        break;

    case IOCTL_QUIC_RUN_ACK_SEND_DELAY:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestAckSendDelay(Params->Family));
        break;

    case IOCTL_QUIC_RUN_CUSTOM_SERVER_CERT_VALIDATION:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestCustomServerCertificateValidation(
                Params->CustomCertValidationParams.AcceptCert,
                Params->CustomCertValidationParams.AsyncValidation));
        break;

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    case IOCTL_QUIC_RUN_VERSION_NEGOTIATION_RETRY:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestVersionNegotiationRetry(Params->Family));
        break;

    case IOCTL_QUIC_RUN_COMPATIBLE_VERSION_NEGOTIATION_RETRY:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestCompatibleVersionNegotiationRetry(Params->Family));
        break;

    case IOCTL_QUIC_RUN_COMPATIBLE_VERSION_NEGOTIATION:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestCompatibleVersionNegotiation(
                Params->VersionNegotiationExtParams.Family,
                Params->VersionNegotiationExtParams.DisableVNEClient,
                Params->VersionNegotiationExtParams.DisableVNEServer));
        break;

    case IOCTL_QUIC_RUN_COMPATIBLE_VERSION_NEGOTIATION_DEFAULT_SERVER:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestCompatibleVersionNegotiationDefaultServer(
                Params->VersionNegotiationExtParams.Family,
                Params->VersionNegotiationExtParams.DisableVNEClient,
                Params->VersionNegotiationExtParams.DisableVNEServer));
        break;

    case IOCTL_QUIC_RUN_COMPATIBLE_VERSION_NEGOTIATION_DEFAULT_CLIENT:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestCompatibleVersionNegotiationDefaultClient(
                Params->VersionNegotiationExtParams.Family,
                Params->VersionNegotiationExtParams.DisableVNEClient,
                Params->VersionNegotiationExtParams.DisableVNEServer));
        break;

    case IOCTL_QUIC_RUN_INCOMPATIBLE_VERSION_NEGOTIATION:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestIncompatibleVersionNegotiation(Params->Family));
        break;

    case IOCTL_QUIC_RUN_FAILED_VERSION_NEGOTIATION:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestFailedVersionNegotiation(Params->Family));
        break;

    case IOCTL_QUIC_RUN_VALIDATE_VERSION_SETTINGS_SETTINGS:
        QuicTestCtlRun(QuicTestVersionSettings());
        break;
#endif // QUIC_API_ENABLE_PREVIEW_FEATURES

    case IOCTL_QUIC_RUN_CONNECT_CLIENT_CERT:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestConnectClientCertificate(
                Params->ConnectClientCertParams.Family,
                Params->ConnectClientCertParams.UseClientCert));
        break;

    case IOCTL_QUIC_RUN_VALID_ALPN_LENGTHS:
        QuicTestCtlRun(QuicTestValidAlpnLengths());
        break;

    case IOCTL_QUIC_RUN_INVALID_ALPN_LENGTHS:
        QuicTestCtlRun(QuicTestInvalidAlpnLengths());
        break;

    case IOCTL_QUIC_RUN_EXPIRED_SERVER_CERT:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        //
        // Fix up pointers for kernel mode
        //
        switch (Params->CredValidationParams.CredConfig.Type) {
        case QUIC_CREDENTIAL_TYPE_NONE:
            Params->CredValidationParams.CredConfig.Principal = (const char*)Params->CredValidationParams.PrincipalString;
            break;
        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH:
            Params->CredValidationParams.CredConfig.CertificateHash = &Params->CredValidationParams.CertHash;
            break;
        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE:
            Params->CredValidationParams.CredConfig.CertificateHashStore = &Params->CredValidationParams.CertHashStore;
            break;
        }

        if (Length < sizeof(QUIC_RUN_TEST_REQUEST) + TestRequest->ParameterSize) {
            Status = STATUS_INVALID_PARAMETER;
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "IOCTL buffer too small for test parameters");
            break;
        }

        // Invoke the test function
        Client->TestFailure = false;
        Status = ExecuteTestRequest(TestRequest);
        if (Status == QUIC_STATUS_SUCCESS && Client->TestFailure) {
            Status = STATUS_FAIL_FAST_EXCEPTION;
        }

        break;
    }

    default:
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            FunctionCode,
            "Invalid FunctionCode");
        Status = STATUS_NOT_IMPLEMENTED;
        break;
    }

Error:

    QuicTraceLogInfo(
        TestControlClientIoctlComplete,
        "[test] Client %p completing request, 0x%x",
        Client,
        Status);

    WdfRequestComplete(Request, Status);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
LogTestFailure(
    _In_z_ const char *File,
    _In_z_ const char *Function,
    int Line,
    _Printf_format_string_ const char *Format,
    ...
    )
/*++

Routine Description:

    Records a test failure from the platform independent test code.

Arguments:

    File - The file where the failure occurred.

    Function - The function where the failure occurred.

    Line - The line (in File) where the failure occurred.

Return Value:

    None

--*/
{
    char Buffer[128];

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    QuicTestClient->TestFailure = true;

    va_list Args;
    va_start(Args, Format);
    (void)_vsnprintf_s(Buffer, sizeof(Buffer), _TRUNCATE, Format, Args);
    va_end(Args);

    QuicTraceLogError(
        TestDriverFailureLocation,
        "[test] File: %s, Function: %s, Line: %d",
        File,
        Function,
        Line);
    QuicTraceLogError(
        TestDriverFailure,
        "[test] FAIL: %s",
        Buffer);

#if QUIC_BREAK_TEST
    NT_FRE_ASSERT(FALSE);
#endif
}
