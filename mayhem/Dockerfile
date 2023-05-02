# Build Stage
FROM bcapuano/atheris:2.1.1-python3.10
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y clang cmake make ninja-build python3 python3-pip git libeccodes-dev
RUN pip3 install Cython atheris cmake

# Install dependencies
ADD . /src
WORKDIR /src
ENV CC="/usr/bin/clang"
ENV CFLAGS="-fsanitize=fuzzer-no-link,address,undefined"
ENV CXX="/usr/bin/clang++"
ENV CXXFLAGS="-fsanitize=fuzzer-no-link,address,undefined -O3"
ENV ASAN_OPTIONS="detect_leaks=0"
RUN python3 -m pip install .
ENV ASAN_OPTIONS="detect_leaks=1"
ENV LD_PRELOAD="${LD_PRELOAD}:/usr/local/lib/python3.10/dist-packages/ubsan_with_fuzzer.so"
ENV LD_PRELOAD="${LD_PRELOAD}:/usr/lib/llvm-14/lib/clang/14.0.0/lib/linux/libclang_rt.ubsan_standalone-x86_64.so"
ENV LD_PRELOAD="${LD_PRELOAD}:/usr/local/lib/python3.10/dist-packages/asan_with_fuzzer.so"
CMD ["/src/mayhem/fuzz_pcode.py"]
