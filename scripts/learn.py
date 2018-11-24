"""Modbus TCP/IP registers learn implementation.

This module exploit the basic assumption that PLC registers
values have periodic/semi-constant behavior.
Learn function input is one of the following:
 - Time period for sniffing traffic between HMI & PLC (Promiscuous or MiTM required)
 - Pcap file with HMI-PLC communication.

In Modbus TCP/IP protocol the master (e.g HMI) send REQUEST to the slave (e.g PLC)
for reading/writing data from/to the registers/coils and the slave RESPONSE with the
requested data.
The data usually represent physical processes or values (start/stop machine,
temperature, water level and so on...).

This module follow the requests and responses and store the data in a matrix
representing the registers values over time.
    m*n - matrix size
    m - time or index
    n - PLC size, number of registers.

Next, for every column in the matrix (each register) we calculate its function using
Spline Interpolation (UnivariateSpline) for monotonically
increasing/decreasing values else 1-D interpolation (interp1d).

The created functions will be used to response the master with 'similar to original'
results in a 1-Way MiTM attack between Modbus master and slave.

USAGE:
from learn import LearnModbus - import class
lmb_object = Model() - declare learning class
"""

import numpy as np
import logging
import os
import sys
import pickle
import time
import matplotlib.pyplot as plt
from config.defaults import cfg
import scripts.interpolation as interp
from tools.network import Network
import datetime

logging.basicConfig(format='%(levelname)s - %(asctime)s - %(message)s',
                    datefmt='%d-%b-%y %H:%M:%S',
                    level=logging.INFO)


class Model:
    """Modbus TCP/IP registers learn implementation."""

    def __init__(self, model_name=None):
        self.learn_time = cfg.LEARN_TIME
        self.matrix = np.zeros((1, cfg.DEVICES.PLC.SIZE + 1), dtype=int)    # pass on 0-th column. reg number = matrix column idx
        self.functions = []
        self.period = 0
        self.model_name = '_'.join([model_name.__str__(), int(time.time()).__str__(), cfg.LEARN_TIME.__str__() + 'sec.pkl'])

    # TODO - Way too slow! run parallel dissections [suggestion: create trans_id queue and add every query ]
    def modbus(self, packets=None):
        logging.info('{} - Start packets dissection'.format(datetime.datetime.now().strftime('%H:%M:%S')))
        error_list = []
        data_dict = {}
        try:
            for packet in packets:
                # TODO - Create state machine - Add Write functions CODE 6, 16, 5, 15 (2D -> 3D matrix)
                try:
                    params = Network.modbus_parser(packet)

                    # QUERY (HMI -> PLC)
                    if packet['TCP'].dport == 502:
                        # save ref_num & wrd_cnt per trans_id for matched response packet.
                        data_dict[params['trans_id']] = [params['reference_num'], params['word_cnt']]

                    # RESPONSE (PLC -> HMI)
                    elif packet['TCP'].sport == 502:
                        self.matrix = np.vstack((self.matrix, self.matrix[-1]))  # add new row (last row copy)
                        reference_num, word_cnt = data_dict.pop(params['trans_id'])
                        d_idx = 18    # modbus data start index (byte 63 of TCP/IP packet)
                        for i in range(reference_num, word_cnt + reference_num):
                            self.matrix[-1][i] = int(params['raw'][d_idx:d_idx + 4], 16)    # save reg data as int
                            d_idx += 4

                except Exception as e:
                    error_list.append(str(e))
                    continue

            logging.info('{} - Done packets dissection'.format(datetime.datetime.now().strftime('%H:%M:%S')))
            # interpolate registers data
            self.matrix, self.functions = interp.run(self.matrix, 'column')
            # export model for future use
            self.export_model()

        except Exception as e:
            logging.warning("Packets dissection errors: {}".format(len(error_list)))
            logging.error("Error occurred during learning phase, closing...", exc_info=True)
            sys.exit(1)

    def modbus_accumulated(self, packets=None):
        logging.info('Start packets dissection')
        error_list = []
        data_dict = {}
        reg_stream_merge = []
        period = [0, 1]
        try:
            for packet in packets:
                # TODO - Create state machine - Add Write functions CODE 6, 16, 5, 15 (2D -> 3D matrix)
                try:
                    params = Network.modbus_parser(packet)

                    # QUERY (HMI -> PLC)
                    if packet['TCP'].dport == 502:
                        # save ref_num & wrd_cnt per trans_id for matched response packet.
                        data_dict[params['trans_id']] = [params['reference_num'], params['word_cnt']]

                    # RESPONSE (PLC -> HMI)
                    elif packet['TCP'].sport == 502:
                        reference_num, word_cnt = data_dict.pop(params['trans_id'])
                        if reference_num in reg_stream_merge:
                            period[0] = (period[0] + len(reg_stream_merge))
                            period[1] += 1
                            reg_stream_merge = []
                            self.matrix = np.vstack((self.matrix, self.matrix[-1]))  # add new row (last row copy)

                        reg_stream_merge.append(reference_num)
                        np.put(self.matrix[-1],
                               np.arange(reference_num, word_cnt + reference_num),
                               [int(params['raw'][d_idx:d_idx + 4], 16) for d_idx in np.arange(18, 18+4*word_cnt, 4)])

                except Exception as e:
                    error_list.append(str(e))
                    continue

            logging.info('Done packets dissection | Period = {}'.format(str(round(period[0]/period[1]))))
            # interpolate registers data
            self.matrix, self.functions = interp.run(self.matrix, 'column')
            # export model for future use
            self.export_model()

        except Exception as e:
            logging.warning("Packets dissection errors: {}".format(len(error_list)))
            logging.error("Error occurred during learning phase, closing...", exc_info=True)
            sys.exit(1)

    def plot_functions(self):
        plots = []
        for idx in range(self.matrix.shape[1]):
            # As register value are positive,
            # zero mean indicate that the register is non-functioning.
            if self.matrix[:, idx].mean() != 0.0:
                plots.append((self.matrix[:, idx], idx))

        fig = plt.figure()
        fig.suptitle('Registers Function', fontsize=10)
        x_values = range(0, self.matrix.shape[0])
        for idx, plot in enumerate(plots):
            plt.subplot(plots.__len__(), idx % 2 + 1, idx + 1)

            y_values_samples = plot[0]
            plt.plot(x_values, y_values_samples, 'r--')

            y_values_interpl = self.functions[plot[1]](x_values)
            plt.plot(x_values, y_values_interpl, 'b')

            plt.ylabel('Reg-' + str(plot[1]))
        plt.show()

    def export_model(self):
        logging.info('Exporting learned model to folder: {}'.format(cfg.MODELS_PATH))
        with open(os.path.join(cfg.MODELS_PATH, self.model_name), 'wb') as f:
            s = [self.functions, self.matrix]
            pickle.dump(s, f)
        logging.info('Model exported: {}'.format(os.path.join(cfg.MODELS_PATH, self.model_name)))

    def load_model(self, file_name):
        self.model_name = file_name
        with open(os.path.join(cfg.MODELS_PATH, self.model_name), 'rb') as f:
            self.functions, self.matrix = pickle.load(f)
        logging.info('Model loaded: {}'.format(self.model_name))
