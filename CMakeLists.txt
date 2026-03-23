# CMakeLists.txt for d0002e scratch programs
# This allows building multiple executables in this directory
#
# Place this entire directory (d0002e/) inside ns-3.46.1/scratch/
# so the path is: ns-3.46.1/scratch/d0002e/CMakeLists.txt

build_exec(
    EXECNAME lab1-with-guidance
    EXECNAME_PREFIX scratch_d0002e_
    SOURCE_FILES lab1-http-dns/lab1-with-guidance.cc
    LIBRARIES_TO_LINK "${ns3-libs}" "${ns3-contrib-libs}"
    EXECUTABLE_DIRECTORY_PATH ${CMAKE_OUTPUT_DIRECTORY}/scratch/d0002e/
)

build_exec(
    EXECNAME lab2
    EXECNAME_PREFIX scratch_d0002e_
    SOURCE_FILES lab2-tcp-udp/lab2-with-guidance.cc
    LIBRARIES_TO_LINK "${ns3-libs}" "${ns3-contrib-libs}"
    EXECUTABLE_DIRECTORY_PATH ${CMAKE_OUTPUT_DIRECTORY}/scratch/d0002e/
)

build_exec(
    EXECNAME lab2-with-guidance
    EXECNAME_PREFIX scratch_d0002e_
    SOURCE_FILES lab2-tcp-udp/lab2-with-guidance.cc
    LIBRARIES_TO_LINK "${ns3-libs}" "${ns3-contrib-libs}"
    EXECUTABLE_DIRECTORY_PATH ${CMAKE_OUTPUT_DIRECTORY}/scratch/d0002e/
)

build_exec(
    EXECNAME lab3
    EXECNAME_PREFIX scratch_d0002e_
    SOURCE_FILES lab3-ip-dataplane/lab3-with-guidance.cc
    LIBRARIES_TO_LINK "${ns3-libs}" "${ns3-contrib-libs}"
    EXECUTABLE_DIRECTORY_PATH ${CMAKE_OUTPUT_DIRECTORY}/scratch/d0002e/
)

build_exec(
    EXECNAME lab3-with-guidance
    EXECNAME_PREFIX scratch_d0002e_
    SOURCE_FILES lab3-ip-dataplane/lab3-with-guidance.cc
    LIBRARIES_TO_LINK "${ns3-libs}" "${ns3-contrib-libs}"
    EXECUTABLE_DIRECTORY_PATH ${CMAKE_OUTPUT_DIRECTORY}/scratch/d0002e/
)

build_exec(
    EXECNAME lab4
    EXECNAME_PREFIX scratch_d0002e_
    SOURCE_FILES lab4-ip-controlplane/lab4-with-guidance.cc
    LIBRARIES_TO_LINK "${ns3-libs}" "${ns3-contrib-libs}"
    EXECUTABLE_DIRECTORY_PATH ${CMAKE_OUTPUT_DIRECTORY}/scratch/d0002e/
)

build_exec(
    EXECNAME lab4-with-guidance
    EXECNAME_PREFIX scratch_d0002e_
    SOURCE_FILES lab4-ip-controlplane/lab4-with-guidance.cc
    LIBRARIES_TO_LINK "${ns3-libs}" "${ns3-contrib-libs}"
    EXECUTABLE_DIRECTORY_PATH ${CMAKE_OUTPUT_DIRECTORY}/scratch/d0002e/
)

build_exec(
    EXECNAME lab5-with-guidance
    EXECNAME_PREFIX scratch_d0002e_
    SOURCE_FILES lab5-link-layer/lab5-with-guidance.cc
    LIBRARIES_TO_LINK "${ns3-libs}" "${ns3-contrib-libs}"
    EXECUTABLE_DIRECTORY_PATH ${CMAKE_OUTPUT_DIRECTORY}/scratch/d0002e/
)

build_exec(
    EXECNAME lab6-with-guidance
    EXECNAME_PREFIX scratch_d0002e_
    SOURCE_FILES lab6-tls/lab6-with-guidance.cc
    LIBRARIES_TO_LINK "${ns3-libs}" "${ns3-contrib-libs}"
    EXECUTABLE_DIRECTORY_PATH ${CMAKE_OUTPUT_DIRECTORY}/scratch/d0002e/
)
