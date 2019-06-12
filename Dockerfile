FROM openresty/openresty:1.13.6.2-2-centos

RUN yum install -y libxml2-devel openssl-devel zlib-devel gcc make && \
    yum clean all -y

ENV XMLSEC_VERSION=1.2.28
RUN curl https://www.aleksey.com/xmlsec/download/xmlsec1-${XMLSEC_VERSION}.tar.gz | tar -xz && \
    cd xmlsec1-${XMLSEC_VERSION} && \
    ./configure --disable-crypto-dl && \
    make && \
    make check && \
    make install && \
    ldconfig /usr/local/lib

RUN luarocks install lua-zlib 1.2-0
