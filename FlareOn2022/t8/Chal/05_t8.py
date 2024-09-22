from flask import Flask, request, Response
import hashlib
from RC4Encryption import RC4Encryption
import base64

app = Flask(__name__)
c = True
@app.route('/', methods=['POST'])
def handle_post():
    global c
    if c:
        dat = b"TdQdBRa1nxGU06dbB27E7SQ7TJ2+cd7zstLXRQcLbmh2nTvDm1p5IfT/Cu0JxShk6tHQBRWwPlo9zA1dISfslkLgGDs41WK12ibWIflqLE4Yq3OYIEnLNjwVHrjL2U4Lu3ms+HQc4nfMWXPgcOHb4fhokk93/AJd5GTuC5z+4YsmgRh1Z90yinLBKB+fmGUyagT6gon/KHmJdvAOQ8nAnl8K/0XG+8zYQbZRwgY6tHvvpfyn9OXCyuct5/cOi8KWgALvVHQWafrp8qB/JtT+t5zmnezQlp3zPL4sj2CJfcUTK5copbZCyHexVD4jJN+LezJEtrDXP1DJNg=="
        dat = base64.b64decode(dat)
        rc4 = RC4Encryption(hashlib.md5('FO911950'.encode('utf-16le')).hexdigest().encode('utf-16le'))
        rc4.make_key()
        ciph = rc4.encrypt(dat)
        print(ciph)
        ua = request.headers.get('User-Agent')
        print(ua)
        randomstr = ('FO9' + ua.split(' ')[-1][:-1]).encode('utf-16le')
        print('FO9' + ua.split(' ')[-1][:-1])
        dat = ciph
        rc4_2 = RC4Encryption(hashlib.md5(randomstr).hexdigest().encode('utf-16le'))
        rc4_2.make_key()
        ciph2 = rc4_2.encrypt(ciph)
        dat = base64.b64encode(ciph2)
        print(dat)
        c = not(c)
        return Response(dat, mimetype='application/octet-stream')
    else:
        dat = 'F1KFlZbNGuKQxrTD/ORwudM8S8kKiL5F906YlR8TKd8XrKPeDYZ0HouiBamyQf9/Ns7u3C2UEMLoCA0B8EuZp1FpwnedVjPSdZFjkieYqWzKA7up+LYe9B4dmAUM2lYkmBSqPJYT6nEg27n3X656MMOxNIHt0HsOD0d+'
        c = not(c)
        return Response(dat, mimetype='application/octet-stream')

if __name__ == '__main__':
    app.run(host="0.0.0.0",port=80)
