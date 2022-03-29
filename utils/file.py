# python imports
import os
import csv


def make_dir(dir_path):
    # create output folder
    # if it doesnt exists
    dirs = os.path.split(dir_path)[0]
    if not os.path.exists(dirs):
        os.makedirs(dirs)


def remove_file(file_path):
    # remove file if it exists
    if os.path.exists(file_path):
        os.remove(file_path)


def save_to_csv(file_path, header, rows):
    with open(file_path, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)
