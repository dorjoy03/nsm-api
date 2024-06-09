FROM fedora:latest

RUN dnf install -y \
    python3 \
    python3-pip

RUN pip3 install cbor2
RUN pip3 install ioctl-opt

WORKDIR /home

COPY test_nsm.py test_nsm.py

CMD ["python3", "/home/test_nsm.py"]
