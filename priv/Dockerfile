FROM ubuntu:cosmic

ARG OTP_VERSION=local
ENV OTP_VERSION ${OTP_VERSION}

RUN apt-get update && \
    apt-get -y install curl gnupg2 && \
    curl -O https://packages.erlang-solutions.com/erlang-solutions_1.0_all.deb && \
    dpkg -i erlang-solutions_1.0_all.deb && \
    apt-get update && \
    apt-get -y install esl-erlang=1:${OTP_VERSION} git make clang-7

ENV CC clang-7
ENV CXX clang++-7

RUN mkdir /build
WORKDIR /build
