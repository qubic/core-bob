#pragma once
#include "global_var.h"

#define MRB_Data                   (GS().MRB_Data)
#define MRB_Request                (GS().MRB_Request)
#define MRB_SC                      (GS().MRB_SC)

#define requestMapperFrom          (GS().requestMapperFrom)
#define requestMapperTo            (GS().requestMapperTo)
#define responseSCData              (GS().responseSCData)

#define gCurrentFetchingTick     (GS().gCurrentProcessingTick)
#define gCurrentProcessingEpoch    (GS().gCurrentProcessingEpoch)
#define gInitialTick               (GS().gInitialTick)
#define gCurrentFetchingLogTick   (GS().gCurrentLoggingEventTick)
#define gCurrentVerifyLoggingTick  (GS().gCurrentVerifyLoggingTick)
#define gCurrentIndexingTick       (GS().gCurrentIndexingTick)
#define gLastSeenNetworkTick        (GS().gLastSeenNetworkTick)
#define gReindexFromTick           (GS().gReindexFromTick)
#define computorsList              (GS().computorsList)

#define spectrum                   ((EntityRecord*)GS().spectrum)
#define assets                     ((AssetRecord*)GS().assets)
#define assetChangeFlags           (GS().assetChangeFlags)
#define spectrumChangeFlags        (GS().spectrumChangeFlags)
#define spectrumDigests            (GS().spectrumDigests)
#define assetDigests               (GS().assetDigests)
#define refetchFromId              (GS().refetchFromId)
#define refetchToId                (GS().refetchToId)
#define refetchLogFromTick             (GS().refetchLogFromTick)
#define refetchLogToTick             (GS().refetchLogToTick)
#define refetchLogFlag             (GS().refetchLogFlag)

#define refetchTickVotes           (GS().refetchTickVotes)
#define gIsEndEpoch (GS().gIsEndEpoch)
#define nodeSubseed                 (GS().nodeSubseed)
#define nodePublickey                 (GS().nodePublickey)
#define nodePrivatekey                 (GS().nodePrivatekey)
#define nodeIdentity (GS().nodeIdentity)
#define gNodeAlias (GS().nodeAlias)
#define gTickStorageMode                 (GS().gTickStorageMode)
#define gLastNTickStorage                 (GS().gLastNTickStorage)

#define gTxStorageMode                 (GS().gTxStorageMode)
#define gTxTickToLive                 (GS().gTxTickToLive)

#define gMaxThreads (GS().gMaxThreads)
#define gSpamThreshold (GS().gSpamThreshold)

#define gNumBMConnection (GS().gNumBMConnection)

#define gKvrocksTTL (GS().gKvrocksTTL)
#define gTimeToWaitEpochEnd (GS().gTimeToWaitEpochEnd)

#define gRpcPort (GS().gRpcPort)
#define gEnableAdminEndpoints (GS().gEnableAdminEndpoints)
#define gAllowReceiveLogFromIncomingConnection (GS().gAllowReceiveLogFromIncomingConnection)
#define gExitDataThreadCounter (GS().gExitDataThreadCounter)
#define gStopFlag (GS().gStopFlag)
#define gStartTimeUnix (GS().startTimeUnix)
#define gAllowCheckInQubicGlobal (GS().allowCheckInQubicGlobal)
#define gTCM (GS().TCM)