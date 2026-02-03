#include "bob.h"
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <vector>
bool bob_client_stop_flag = false;
bool is_watchdog = true;
static void onSigInt(int) {
    if (!bob_client_stop_flag)
    {
        if (!is_watchdog) requestToExitBob(); // watchdog process doesn't run bob actually
        bob_client_stop_flag = true;
    }
    else
    {
        printf("Pressed Ctrl+C twice, killing the process...\n");
        exit(3);
    }
}

void installCtrlCPrinter() {
    std::signal(SIGINT, &onSigInt);
}

int main(int argc, char *argv[]) {
    if (argc == 3)
    {
        if (std::string(argv[2]) == "-no-watchdog") is_watchdog = false;
    }
    installCtrlCPrinter();
    if (is_watchdog)
    {
        std::string command = std::string(argv[0]) + " ";
        if (argc > 1) command += std::string(argv[1]) + " -no-watchdog";
        else command += "bob.json -no-watchdog";
        while (true){
            int r = system(command.c_str());
            printf("bob exited with code %d, if you want to exit bob completely, press Ctrl+C one more time\n", r);
            printf("sleep for 2 seconds and start again\n");
            if (bob_client_stop_flag) break;
            std::this_thread::sleep_for(std::chrono::seconds (2));
        }
    }
    else
    {
        try {
            return runBob(argc, argv);
        }
        catch (std::exception &ex) {
            printf("%s", ex.what());
            return -1;
        }
    }
    return 0;
}
