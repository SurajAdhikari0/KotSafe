cmake_minimum_required(VERSION 3.18)
project(kotengine C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(KOTENGINE_SOURCES
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
    network_policy.c
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
)

add_library(kotengine SHARED ${KOTENGINE_SOURCES} jni_bridge.c)

target_include_directories(kotengine PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(ANDROID)
    find_library(log-lib log)
    target_link_libraries(kotengine ${log-lib} m)
else()
    target_link_libraries(kotengine pthread m)
endif()

target_compile_options(kotengine PRIVATE -Wall -Wextra -O2)

if(NOT ANDROID)
    include(CTest)
    if(BUILD_TESTING)
        add_executable(test_network_policy test_network_policy.c network_policy.c firewall.c blacklist.c)
        target_link_libraries(test_network_policy pthread)
        target_compile_options(test_network_policy PRIVATE -Wall -Wextra -Werror)
        add_test(NAME network_policy COMMAND test_network_policy)
        add_executable(test_firewall test_firewall.c firewall.c)
        target_link_libraries(test_firewall pthread)
        target_compile_options(test_firewall PRIVATE -Wall -Wextra -Werror)
        add_test(NAME firewall COMMAND test_firewall)
        add_executable(test_capture_policy test_capture_policy.c ${KOTENGINE_SOURCES})
        target_include_directories(test_capture_policy PRIVATE host_test)
        target_link_libraries(test_capture_policy pthread m)
        target_compile_options(test_capture_policy PRIVATE -Wall -Wextra)
        add_test(NAME capture_policy COMMAND test_capture_policy)
    endif()
endif()
