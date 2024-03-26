#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <pcap.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <thread>
#include <mutex>
#include <map>
#include <atomic>
#include <chrono>
#include <algorithm>

using namespace std;

// Globalne zmienne
mutex mtx; // Mutex dla synchronizacji między wątkami
map<string, atomic<bool>> activeCaptures; // Mapa do śledzenia aktywnych przechwyceń dla różnych IP

// Funkcja zwracająca aktualną datę i czas
string getCurrentDateTime() {
    auto now = time(nullptr);
    ostringstream ss;
    ss << put_time(localtime(&now), "%Y-%m-%d_%H-%M-%S");
    return ss.str();
}

// Funkcja obsługi pakietów, wywoływana dla każdego przechwyconego pakietu
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    pcap_dump(userData, pkthdr, packet);
}

// Główna funkcja do przechwytywania pakietów
void capturePackets(const string& ip) {
    string dev = "wlx5ce9316836f6"; // Nazwa interfejsu sieciowego

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        cerr << "Couldn't open device " << dev << ": " << errbuf << endl;
        return;
    }

    string filter = "ip host " + ip;
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        cerr << "Couldn't parse filter " << filter << ": " << pcap_geterr(handle) << endl;
        return;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        cerr << "Couldn't install filter " << filter << ": " << pcap_geterr(handle) << endl;
        return;
    }

    string fileName = "logs/packets_" + ip + "_" + getCurrentDateTime() + ".pcap";
    pcap_dumper_t *dumper = pcap_dump_open(handle, fileName.c_str());
    if (dumper == nullptr) {
        cerr << "Could not open file for writing: " << pcap_geterr(handle) << endl;
        return;
    }

    while (activeCaptures[ip]) {
        pcap_dispatch(handle, 0, packetHandler, reinterpret_cast<u_char*>(dumper));
    }

    pcap_dump_close(dumper);
    pcap_close(handle);
    cout << "Stopped capturing for IP " << ip << endl;
}

// Funkcja do rozpoczynania przechwytywania pakietów
void startCapture(const string& ip) {
    activeCaptures[ip] = true;
    thread(capturePackets, ip).detach();
}

// Funkcja do zatrzymywania przechwytywania pakietów
void stopCapture(const string& ip) {
    if (activeCaptures.find(ip) != activeCaptures.end()) {
        activeCaptures[ip] = false; // To zatrzyma pętlę w capturePackets
    }
}

// Funkcja do pobierania listy połączonych adresów IP
vector<string> getConnectedIPs() {
    vector<string> ips;
    const char* interface = "wlx5ce9316836f6"; // Nazwa interfejsu sieciowego

    FILE* pipe = popen(("sudo arp-scan --interface=" + string(interface) + " --localnet | awk 'NR>=3 && NF{print $1} NF==0{exit}'").c_str(), "r");
    if (!pipe) {
        cerr << "Error opening pipe!" << endl;
        return ips;
    }

    char buffer[128];
    while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe) != NULL) {
            ips.push_back(string(buffer));
        }
    }
    pclose(pipe);
    return ips;
}

// Główna funkcja programu
int main() {
    while (true) {
        vector<string> ips = getConnectedIPs();
        lock_guard<mutex> lock(mtx);

        // Rozpoczynanie przechwytywania dla nowych IP
        for (const auto& ip : ips) {
            if (activeCaptures.find(ip) == activeCaptures.end()) {
                cout << "Rozpoczęto zapis dla: " << ip << endl;
                thread(startCapture, ip).detach();
            }
        }

        // Zatrzymywanie przechwytywania dla IP, które już nie są połączone
        for (auto& capture : activeCaptures) {
            if (find(ips.begin(), ips.end(), capture.first) == ips.end()) {
                thread(stopCapture, capture.first).detach();
            }
        }

        this_thread::sleep_for(chrono::seconds(5));
    }

    return 0;
}
