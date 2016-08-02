import os

def clear_dir(dir_path):
    for file_name in os.listdir(dir_path):
        file_path = os.path.join(dir_path, file_name)
        try:
            if os.path.isfile(file_path):
                os.unlink(file_path)
        except Exception as e:
            log.fatal(e)


def ensure_dir(dir_path):
    if not os.path.exists(dir_path):
        # if directory does not exit, create it
        os.makedirs(dir_path)
    else:
        # if directory already exists, clear directory
        clear_dir(dir_path)