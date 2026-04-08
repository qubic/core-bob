// LoggingEventProcessorCore.h
#pragma once
#include "structs.h"
#include "LogEvent.h"
#include <vector>
#include <cstdint>

void processQuTransfer(const QuTransfer& qt, uint32_t tick);
void processQuTransfer(LogEvent& le);
void processQuBurn(LogEvent& le);
bool processDistributeDividends(std::vector<LogEvent>& vle);
void processIssueAsset(LogEvent& le);
void processChangeOwnershipAndPossession(LogEvent& le0, LogEvent& le1);
void processChangeManagingContract(LogEvent& le0, LogEvent& le1);
bool processSendToManyBenchmark(LogEvent& le);