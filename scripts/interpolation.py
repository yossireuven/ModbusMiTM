"""Modbus_MiTM - Yossi Reuven
Functions interpolation module.
"""

import numpy as np
from scipy import interpolate
import logging

logging.basicConfig(format='%(levelname)s - %(asctime)s - %(message)s',
                    datefmt='%d-%b-%y %H:%M:%S',
                    level=logging.INFO)


def run(matrix, direction='column'):
    """
    For given matrix and direction this function
    create functions using Spline/1D interpolation.
    :param matrix: 2-D numpy array (RxC)
    :param direction: 2-D numpy array (RxC)
    :return: processes matrix, interpolated functions
    """
    logging.info("Interpolating over data...")
    axis = {'row': 0, 'column': 1}[direction]
    functions = []
    matrix = pre_processing(matrix, axis)
    x_values = range(matrix.shape[1-axis])
    for vector_idx in range(matrix.shape[axis]):
        y_values = matrix[:, vector_idx] if axis else matrix[vector_idx, :]
        functions.append(interpolate.InterpolatedUnivariateSpline(x_values, y_values))
    logging.info("Functions created successfully.")
    return matrix, functions


def pre_processing(matrix, axis=1):
    """
    Matrix pre-processing -
    delete  0.5%  of vectors in %axis% (error margin)
    :param matrix: 2-D numpy array (RxC)
    :param axis: Interpolation direction (row or column)
    :return: processed matrix
    """
    return np.delete(matrix, slice(round(matrix.shape[1-axis] * 0.005),), axis=1-axis)
