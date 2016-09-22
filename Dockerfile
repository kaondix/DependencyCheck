#
# OpenJDK Java 7 JDK Dockerfile
#
# https://github.com/dockerfile/java
# https://github.com/dockerfile/java/tree/master/openjdk-7-jdk
#

# Pull base image.
FROM ubuntu:14.04

# Install Java.
RUN \
  sed -i 's/# \(.*multiverse$\)/\1/g' /etc/apt/sources.list && \
  apt-get update && \
  apt-get -y upgrade && \
  apt-get install -y build-essential && \
  apt-get install -y software-properties-common && \
  apt-get install -y byobu curl git htop man unzip vim wget && \
  apt-get update && \
  apt-get install -y openjdk-7-jdk && \
  rm -rf /var/lib/apt/lists/*


# Java Version and other ENV
ENV JAVA_HOME=/usr/lib/jvm/java-7-openjdk-amd64 \
    DOWNLOAD=https://bintray.com/jeremy-long/owasp/download_file?file_path=dependency-check-1.4.2-release.zip

RUN curl -L ${DOWNLOAD} -o ./dependency-check.zip && \
  unzip dependency-check.zip

WORKDIR /dependency-check/bin

ENTRYPOINT ["/bin/sh", "dependency-check.sh"]