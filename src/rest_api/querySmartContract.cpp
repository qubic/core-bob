#include "src/shim.h"
#include "src/connection/connection.h"
#include <atomic>

void querySmartContractThread(ConnectionPool& connPoolAll)
{
    std::vector<uint8_t> buffer;
    buffer.reserve(0xffffff);
    uint32_t size = 0;
    while (!gStopFlag.load())
    {
        buffer.resize(0xffffff);
        if (MRB_SC.TryGetPacket(buffer.data(), size))
        {
            buffer.resize(size);
            if (size)
            {
                auto header = (RequestResponseHeader*)buffer.data();
                if (header->size() == size)
                {
                    if (header->type() == RequestContractFunction::type)
                    {
                        connPoolAll.sendToRandomBM(buffer.data(), buffer.size());
                    }
                    if (header->type() == BROADCAST_TRANSACTION)
                    {
                        connPoolAll.sendToRandomBM(buffer.data(), buffer.size());
                    }
                }
            }
        }
        else
        {
            SLEEP(5);
        }
    }
}