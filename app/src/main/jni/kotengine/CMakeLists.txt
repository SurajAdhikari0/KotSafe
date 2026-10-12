cmake_minimum_required(VERSION 3.18)
project(kotengine C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(kotengine SHARED
    conn_table.c
    blacklist.c
    ring_log.c
    pcapng_writer.c
    pcap_reader.c
    l7_inspect.c
    geoip.c
    payload_buffer.c
    pcap_stream_server.c
    forward.c
    dns_policy.c
    dns_cache.c
    dns_sinkhole.c
    firewall.c
    proxy_relay.c
    pcapng_secrets.c
    quic_inspect.c
    flow_meter.c
    threat_detector.c
    packet_ring.c
    capture_engine.c
    entropy.c
    ja4.c
    jni_bridge.c
)

target_include_directories(kotengine PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(ANDROID)
    find_library(log-lib log)
    target_link_libraries(kotengine ${log-lib} m)
else()
    target_link_libraries(kotengine pthread m)
endif()

target_compile_options(kotengine PRIVATE -Wall -Wextra -O2)
