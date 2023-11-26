import pathlib
def convert_bytes(size):
    """ Convert bytes to KB, or MB or GB"""
    for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return "%3.1f %s" % (size, x)
        size /= 1024.0
path = pathlib.Path(r'C:/Users/pawan/Desktop/hms project/HMS using blockchain/templates/patient.html')
f_size = path.stat().st_size
x = convert_bytes(f_size)
print('file size is', x)