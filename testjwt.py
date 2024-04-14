import jwt

password = "el>YHbiS>+V64$3gAln(HQC>"

# commentt
def bad1():
    # ruleid: jwt-python-none-alg
    encoded = jwt.encode({"some": "payload"}, None, algorithm="none")
    encoded = jwt.encode({"some": "payload"}, None, algorithm="none")
    encoded = jwt.encode({"some": "payload"}, None, algorithm="none")
    encoded = jwt.encode({"some": "payload"}, None, algorithm="none")
    encoded = jwt.encode({"some": "payload"}, None, algorithm="none")
    return encoded
