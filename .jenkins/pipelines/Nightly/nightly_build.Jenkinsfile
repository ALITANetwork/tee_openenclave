// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

@Library("OpenEnclaveCommon") _
oe = new jenkins.common.Openenclave()

GLOBAL_TIMEOUT_MINUTES = 240
CTEST_TIMEOUT_SECONDS = 480
GLOBAL_ERROR = null

DOCKER_TAG = env.DOCKER_TAG ?: "latest"
AGENTS_LABELS = [
    "acc-ubuntu-16.04": env.UBUNTU_1604_CUSTOM_LABEL ?: "ACC-1604",
    "acc-ubuntu-18.04": env.UBUNTU_1804_CUSTOM_LABEL ?: "ACC-1804",
    "ubuntu-nonsgx":    env.UBUNTU_NONSGX_CUSTOM_LABEL ?: "nonSGX",
    "acc-rhel-8":       env.RHEL_8_CUSTOM_LABEL ?: "ACC-RHEL-8",
    "acc-win2016":      env.WINDOWS_2016_CUSTOM_LABEL ?: "SGXFLC-Windows",
    "acc-win2016-dcap": env.WINDOWS_2016_DCAP_CUSTOM_LABEL ?: "SGXFLC-Windows-DCAP",
    "windows-nonsgx":   env.WINDOWS_NONSGX_CUSTOM_LABEL ?: "nonSGX-Windows"
]


def ACCTest(String label, String compiler, String build_type, String lvi_mitigation = 'None', String lvi_mitigation_tests = 'OFF') {
    stage("${label} ${compiler} SGX1FLC ${build_type} LVI_MITIGATION=${lvi_mitigation}") {
        node("${label}") {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def task = """
                           cmake ${WORKSPACE}                                         \
                               -G Ninja                                               \
                               -DCMAKE_BUILD_TYPE=${build_type}                       \
                               -DLVI_MITIGATION=${lvi_mitigation}                     \
                               -DLVI_MITIGATION_BINDIR=/usr/local/lvi-mitigation/bin  \
                               -DENABLE_LVI_MITIGATION_TESTS=${lvi_mitigation_tests}  \
                               -Wdev
                           ninja -v
                           ctest --output-on-failure --timeout ${CTEST_TIMEOUT_SECONDS}
                           """
                oe.Run(compiler, task)
            }
        }
    }
}

def ACCGNUTest() {
    stage("ACC1804 GNU gcc SGX1FLC") {
        node(AGENTS_LABELS["acc-ubuntu-18.04"]) {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def task = """
                           cmake ${WORKSPACE} -DHAS_QUOTE_PROVIDER=ON
                           make
                           ctest --output-on-failure --timeout ${CTEST_TIMEOUT_SECONDS}
                           """
                oe.Run("gcc", task)
            }
        }
    }
}

def simulationTest(String version, String platform_mode, String build_type, String lvi_mitigation = 'None', String lvi_mitigation_tests = 'OFF') {
    def has_quote_provider = "OFF"
    if (platform_mode == "SGX1FLC") {
        has_quote_provider = "ON"
    }
    stage("Sim clang-7 Ubuntu${version} ${platform_mode} ${build_type} LVI_MITIGATION=${lvi_mitigation}") {
        node(AGENTS_LABELS["ubuntu-nonsgx"]) {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                withEnv(["OE_SIMULATION=1"]) {
                    def task = """
                               cmake ${WORKSPACE}                                          \
                                    -G Ninja                                               \
                                    -DCMAKE_BUILD_TYPE=${build_type}                       \
                                    -DHAS_QUOTE_PROVIDER=${has_quote_provider}             \
                                    -DLVI_MITIGATION=${lvi_mitigation}                     \
                                    -DLVI_MITIGATION_BINDIR=/usr/local/lvi-mitigation/bin  \
                                    -DENABLE_LVI_MITIGATION_TESTS=${lvi_mitigation_tests}  \
                                    -Wdev
                               ninja -v
                               ctest --output-on-failure --timeout ${CTEST_TIMEOUT_SECONDS}
                               """
                    oe.ContainerRun("oetools-full-${version}:${DOCKER_TAG}", "clang-7", task, "--cap-add=SYS_PTRACE")
                }
            }
        }
    }
}

def AArch64GNUTest(String version, String build_type) {
    stage("AArch64 GNU gcc Ubuntu${version} ${build_type}") {
        node(AGENTS_LABELS["ubuntu-nonsgx"]) {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def task = """
                            cmake ${WORKSPACE}                                                     \
                                -G Ninja                                                           \
                                -DCMAKE_BUILD_TYPE=${build_type}                                   \
                                -DCMAKE_TOOLCHAIN_FILE=${WORKSPACE}/cmake/arm-cross.cmake          \
                                -DOE_TA_DEV_KIT_DIR=/devkits/vexpress-qemu_armv8a/export-ta_arm64  \
                                -DHAS_QUOTE_PROVIDER=OFF                                           \
                                -Wdev
                            ninja -v
                            """
                oe.ContainerRun("oetools-full-${version}:${DOCKER_TAG}", "cross", task, "--cap-add=SYS_PTRACE")
            }
        }
    }
}

def ACCContainerTest(String label, String version, String lvi_mitigation = 'None', String lvi_mitigation_tests = 'OFF') {
    stage("${label} Container RelWithDebInfo LVI_MITIGATION=${lvi_mitigation}") {
        node("${label}") {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def task = """
                           cmake ${WORKSPACE}                                         \
                               -G Ninja                                               \
                               -DCMAKE_BUILD_TYPE=RelWithDebInfo                      \
                               -DLVI_MITIGATION=${lvi_mitigation}                     \
                               -DLVI_MITIGATION_BINDIR=/usr/local/lvi-mitigation/bin  \
                               -DENABLE_LVI_MITIGATION_TESTS=${lvi_mitigation_tests}  \
                               -Wdev
                           ninja -v
                           ctest --output-on-failure --timeout ${CTEST_TIMEOUT_SECONDS}
                           """
                oe.ContainerRun("oetools-full-${version}:${DOCKER_TAG}", "clang-7", task, "--cap-add=SYS_PTRACE --device /dev/sgx:/dev/sgx")
            }
        }
    }
}

def ACCPackageTest(String label, String version, String lvi_mitigation = 'None', String lvi_mitigation_tests = 'OFF') {
    stage("${label} Container RelWithDebInfo LVI_MITIGATION=${lvi_mitigation}") {
        node("${label}") {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def task = """
                           cmake ${WORKSPACE}                                       \
                             -G Ninja                                               \
                             -DCMAKE_BUILD_TYPE=RelWithDebInfo                      \
                             -DCMAKE_INSTALL_PREFIX:PATH='/opt/openenclave'         \
                             -DCPACK_GENERATOR=DEB                                  \
                             -DLVI_MITIGATION=${lvi_mitigation}                     \
                             -DLVI_MITIGATION_BINDIR=/usr/local/lvi-mitigation/bin  \
                             -DENABLE_LVI_MITIGATION_TESTS=${lvi_mitigation_tests}  \
                             -Wdev
                           ninja -v
                           ninja -v package
                           sudo ninja -v install
                           cp -r /opt/openenclave/share/openenclave/samples ~/
                           cd ~/samples
                           source /opt/openenclave/share/openenclave/openenclaverc
                           for i in *; do
                               if [ -d \${i} ]; then
                                   cd \${i}
                                   mkdir build
                                   cd build
                                   cmake ..
                                   make
                                   make run
                                   cd ../..
                               fi
                           done
                           """
                oe.ContainerRun("oetools-full-${version}:${DOCKER_TAG}", "clang-7", task, "--cap-add=SYS_PTRACE --device /dev/sgx:/dev/sgx")
            }
        }
    }
}

def checkDevFlows(String version) {
    stage('Default compiler') {
        node(AGENTS_LABELS["ubuntu-nonsgx"]) {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def task = """
                           cmake ${WORKSPACE} -G Ninja -DHAS_QUOTE_PROVIDER=OFF -Wdev --warn-uninitialized -Werror=dev
                           ninja -v
                           """
                oe.ContainerRun("oetools-full-${version}:${DOCKER_TAG}", "clang-7", task, "--cap-add=SYS_PTRACE")
            }
        }
    }
}

def checkCI() {
    stage('Check CI') {
        node(AGENTS_LABELS["ubuntu-nonsgx"]) {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                // At the moment, the check-ci script assumes that it's executed from the
                // root source code directory.
                oe.ContainerRun("oetools-minimal-18.04:${DOCKER_TAG}", "clang-7", "cd ${WORKSPACE} && ./scripts/check-ci", "--cap-add=SYS_PTRACE")
            }
        }
    }
}

def win2016LinuxElfBuild(String version, String compiler, String build_type, String lvi_mitigation = 'None', String lvi_mitigation_tests = 'OFF') {
    stage("Ubuntu ${version} SGX1 ${compiler} ${build_type} LVI_MITIGATION=${lvi_mitigation}") {
        node(AGENTS_LABELS["ubuntu-nonsgx"]) {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def task = """
                           cmake ${WORKSPACE}                                         \
                               -G Ninja                                               \
                               -DCMAKE_BUILD_TYPE=${build_type}                       \
                               -DHAS_QUOTE_PROVIDER=ON                                \
                               -DLVI_MITIGATION=${lvi_mitigation}                     \
                               -DLVI_MITIGATION_BINDIR=/usr/local/lvi-mitigation/bin  \
                               -DENABLE_LVI_MITIGATION_TESTS=${lvi_mitigation_tests}  \
                               -Wdev
                           ninja -v
                           """
                oe.ContainerRun("oetools-full-${version}:${DOCKER_TAG}", compiler, task, "--cap-add=SYS_PTRACE")
                stash includes: 'build/tests/**', name: "linux-${compiler}-${build_type}-lvi_mitigation=${lvi_mitigation}-${version}-${BUILD_NUMBER}"
            }
        }
    }
    stage("Windows ${build_type} LVI_MITIGATION=${lvi_mitigation}") {
        node(AGENTS_LABELS["acc-win2016-dcap"]) {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                unstash "linux-${compiler}-${build_type}-lvi_mitigation=${lvi_mitigation}-${version}-${BUILD_NUMBER}"
                bat 'move build linuxbin'
                dir('build') {
                  bat """
                      vcvars64.bat x64 && \
                      cmake.exe ${WORKSPACE} -G Ninja -DADD_WINDOWS_ENCLAVE_TESTS=ON -DBUILD_ENCLAVES=OFF -DHAS_QUOTE_PROVIDER=ON -DCMAKE_BUILD_TYPE=${build_type} -DLINUX_BIN_DIR=${WORKSPACE}\\linuxbin\\tests -DLVI_MITIGATION=${lvi_mitigation} -DENABLE_LVI_MITIGATION_TESTS=${lvi_mitigation_tests} -DNUGET_PACKAGE_PATH=C:/oe_prereqs -Wdev && \
                      ninja -v && \
                      ctest.exe -V -C ${build_type} --timeout ${CTEST_TIMEOUT_SECONDS}
                      """
                }
            }
        }
    }
}

def win2016CrossCompile(String build_type, String has_quote_provider = 'OFF', String lvi_mitigation = 'None', String lvi_mitigation_tests = 'OFF', String OE_SIMULATION = "0") {
    def node_label = AGENTS_LABELS["acc-win2016"]
    if (has_quote_provider == "ON") {
        node_label = AGENTS_LABELS["acc-win2016-dcap"]
    }
    stage("Windows ${build_type} with SGX ${has_quote_provider} LVI_MITIGATION=${lvi_mitigation}") {
        node(node_label) {
            withEnv(["OE_SIMULATION=${OE_SIMULATION}"]) {
                timeout(GLOBAL_TIMEOUT_MINUTES) {
                    oe.WinCompilePackageTest("build/X64-${build_type}", build_type, has_quote_provider, CTEST_TIMEOUT_SECONDS, lvi_mitigation)
                }
            }
        }
    }
}

def ACCHostVerificationTest(String version, String build_type) {

        /* Compile tests in SGX machine.  This will generate the necessary certs for the
        * host_verify test.
        */
        stage("ACC-1804 Generate Quote") {
            node(AGENTS_LABELS["acc-ubuntu-18.04"]) {
                timeout(GLOBAL_TIMEOUT_MINUTES) {
                    cleanWs()
                    checkout scm

                    println("Generating certificates and reports ...")
                    def task = """
                            cmake ${WORKSPACE} -G Ninja -DHAS_QUOTE_PROVIDER=ON -DCMAKE_BUILD_TYPE=${build_type} -Wdev
                            ninja -v
                            pushd tests/host_verify/host
                            openssl ecparam -name prime256v1 -genkey -noout -out keyec.pem
                            openssl ec -in keyec.pem -pubout -out publicec.pem
                            openssl genrsa -out keyrsa.pem 2048
                            openssl rsa -in keyrsa.pem -outform PEM -pubout -out publicrsa.pem
                            ../../tools/oecert/host/oecert ../../tools/oecert/enc/oecert_enc --cert keyec.pem publicec.pem --out sgx_cert_ec.der
                            ../../tools/oecert/host/oecert ../../tools/oecert/enc/oecert_enc --cert keyrsa.pem publicrsa.pem --out sgx_cert_rsa.der
                            ../../tools/oecert/host/oecert ../../tools/oecert/enc/oecert_enc --report --out sgx_report.bin
                            popd
                            """
                    oe.ContainerRun("oetools-full-${version}:${DOCKER_TAG}", "clang-7", task, "--cap-add=SYS_PTRACE --device /dev/sgx:/dev/sgx")

                    def ec_cert_created = fileExists 'build/tests/host_verify/host/sgx_cert_ec.der'
                    def rsa_cert_created = fileExists 'build/tests/host_verify/host/sgx_cert_rsa.der'
                    def report_created = fileExists 'build/tests/host_verify/host/sgx_report.bin'
                    if (ec_cert_created) {
                        println("EC cert file created successfully!")
                    } else {
                        error("Failed to create EC cert file.")
                    }
                    if (rsa_cert_created) {
                        println("RSA cert file created successfully!")
                    } else {
                        error("Failed to create RSA cert file.")
                    }
                    if (report_created) {
                        println("SGX report file created successfully!")
                    } else {
                        error("Failed to create SGX report file.")
                    }

                    stash includes: 'build/tests/host_verify/host/*.der,build/tests/host_verify/host/*.bin', name: "linux_host_verify-${version}-${build_type}-${BUILD_NUMBER}"
                }
            }
        }

        /* Compile the tests with HAS_QUOTE_PROVIDER=OFF and unstash the certs over for verification.  */
        stage("Linux nonSGX Verify Quote") {
            node(AGENTS_LABELS["ubuntu-nonsgx"]) {
                timeout(GLOBAL_TIMEOUT_MINUTES) {
                    cleanWs()
                    checkout scm
                    unstash "linux_host_verify-${version}-${build_type}-${BUILD_NUMBER}"
                    def task = """
                            cmake ${WORKSPACE} -G Ninja -DBUILD_ENCLAVES=OFF -DHAS_QUOTE_PROVIDER=OFF -DCMAKE_BUILD_TYPE=${build_type} -Wdev
                            ninja -v
                            ctest -R host_verify --output-on-failure --timeout ${CTEST_TIMEOUT_SECONDS}
                            """
                    // Note: Include the commands to build and run the quote verification test above
                    oe.ContainerRun("oetools-full-${version}:${DOCKER_TAG}", "clang-7", task, "--cap-add=SYS_PTRACE")
                }
            }
        }

        /* Windows nonSGX stage. */
        stage("Windows nonSGX Verify Quote") {
            node(AGENTS_LABELS["windows-nonsgx"]) {
                timeout(GLOBAL_TIMEOUT_MINUTES) {
                    cleanWs()
                    checkout scm
                    unstash "linux_host_verify-${version}-${build_type}-${BUILD_NUMBER}"
                    dir('build') {
                        bat """
                            vcvars64.bat x64 && \
                            cmake.exe ${WORKSPACE} -G Ninja -DBUILD_ENCLAVES=OFF -DHAS_QUOTE_PROVIDER=OFF -DCMAKE_BUILD_TYPE=${build_type} -DNUGET_PACKAGE_PATH=C:/oe_prereqs -Wdev && \
                            ninja -v && \
                            ctest.exe -V -C ${build_type} -R host_verify --output-on-failure --timeout ${CTEST_TIMEOUT_SECONDS}
                            """
                    }
                }
            }
        }
 }

def RHEL8Test(String compiler, String build_type, List test_env = []) {
    stage("ACC-RHEL-8 ${compiler} ${build_type}, test_env: ${test_env}") {
        node(AGENTS_LABELS["acc-rhel-8"]) {
            timeout(GLOBAL_TIMEOUT_MINUTES) {
                cleanWs()
                checkout scm
                def task = """
                           cmake ${WORKSPACE} -G Ninja -DCMAKE_BUILD_TYPE=${build_type} -DHAS_QUOTE_PROVIDER=OFF -Wdev
                           ninja -v
                           ctest --output-on-failure --timeout ${CTEST_TIMEOUT_SECONDS}
                           """
                withEnv(test_env) {
                    oe.Run(compiler, task)
                }
            }
        }
    }
}

properties([buildDiscarder(logRotator(artifactDaysToKeepStr: '90',
                                      artifactNumToKeepStr: '180',
                                      daysToKeepStr: '90',
                                      numToKeepStr: '180')),
            [$class: 'JobRestrictionProperty']])

try{
    oe.emailJobStatus('STARTED')
    parallel "Host verification 1604 Debug" :                          { ACCHostVerificationTest('16.04', 'Debug') },
            "Host verification 1604 Release" :                         { ACCHostVerificationTest('16.04', 'Release') },
            "Host verification 1804 Debug" :                           { ACCHostVerificationTest('18.04', 'Debug') },
            "Host verification 1804 Release" :                         { ACCHostVerificationTest('18.04', 'Release') },
            "Win2016 Ubuntu1604 clang-7 Debug Linux-Elf-build" :       { win2016LinuxElfBuild('16.04', 'clang-7', 'Debug') },
            "Win2016 Ubuntu1604 clang-7 Release Linux-Elf-build" :     { win2016LinuxElfBuild('16.04', 'clang-7', 'Release') },
            "Win2016 Ubuntu1604 clang-7 Debug Linux-Elf-build LVI" :   { win2016LinuxElfBuild('16.04', 'clang-7', 'Debug', 'ControlFlow', 'ON') },
            "Win2016 Ubuntu1604 clang-7 Release Linux-Elf-build LVI" : { win2016LinuxElfBuild('16.04', 'clang-7', 'Release', 'ControlFlow', 'ON') },
            "Win2016 Ubuntu1804 clang-7 Debug Linux-Elf-build" :       { win2016LinuxElfBuild('18.04', 'clang-7', 'Debug') },
            "Win2016 Ubuntu1804 clang-7 Release Linux-Elf-build" :     { win2016LinuxElfBuild('18.04', 'clang-7', 'Release') },
            "Win2016 Ubuntu1804 clang-7 Debug Linux-Elf-build LVI" :   { win2016LinuxElfBuild('18.04', 'clang-7', 'Debug', 'ControlFlow', 'ON') },
            "Win2016 Ubuntu1804 clang-7 Release Linux-Elf-build LVI" : { win2016LinuxElfBuild('18.04', 'clang-7', 'Release', 'ControlFlow', 'ON') },
            "Win2016 Ubuntu1804 gcc Debug Linux-Elf-build" :           { win2016LinuxElfBuild('18.04', 'gcc', 'Debug') },
            "Win2016 Ubuntu1804 gcc Debug Linux-Elf-build LVI" :       { win2016LinuxElfBuild('18.04', 'gcc', 'Debug', 'ControlFlow', 'ON') },
            "Win2016 Sim Debug Cross Compile" :                        { win2016CrossCompile('Debug', 'OFF', 'None', '1') },
            "Win2016 Sim Release Cross Compile" :                      { win2016CrossCompile('Release','OFF', 'None', '1') },
            "Win2016 Sim Debug Cross Compile LVI " :                   { win2016CrossCompile('Debug', 'OFF', 'ControlFlow', 'ON', '1') },
            "Win2016 Sim Release Cross Compile LVI " :                 { win2016CrossCompile('Release', 'OFF', 'ControlFlow', 'ON', '1') },
            "Win2016 Debug Cross Compile with DCAP libs" :             { win2016CrossCompile('Debug', 'ON') },
            "Win2016 Release Cross Compile with DCAP libs" :           { win2016CrossCompile('Release', 'ON') },
            "Win2016 Debug Cross Compile DCAP LVI" :                   { win2016CrossCompile('Debug', 'ON', 'ControlFlow', 'ON') },
            "Win2016 Release Cross Compile DCAP LVI" :                 { win2016CrossCompile('Release', 'ON', 'ControlFlow', 'ON') },
            "Check Developer Experience Ubuntu 16.04" :                { checkDevFlows('16.04') },
            "Check Developer Experience Ubuntu 18.04" :                { checkDevFlows('18.04') },
            "Check CI" :                                               { checkCI() },
            "ACC1604 clang-7 Debug" :                                  { ACCTest(AGENTS_LABELS["acc-ubuntu-16.04"], 'clang-7', 'Debug') },
            "ACC1604 clang-7 Release" :                                { ACCTest(AGENTS_LABELS["acc-ubuntu-16.04"], 'clang-7', 'Release') },
            "ACC1604 clang-7 Debug LVI" :                              { ACCTest(AGENTS_LABELS["acc-ubuntu-16.04"], 'clang-7', 'Debug', 'ControlFlow', 'ON') },
            "ACC1604 clang-7 Release LVI" :                            { ACCTest(AGENTS_LABELS["acc-ubuntu-16.04"], 'clang-7', 'Release', 'ControlFlow', 'ON') },
            "ACC1604 gcc Debug" :                                      { ACCTest(AGENTS_LABELS["acc-ubuntu-16.04"], 'gcc', 'Debug') },
            "ACC1604 gcc Release" :                                    { ACCTest(AGENTS_LABELS["acc-ubuntu-16.04"], 'gcc', 'Release') },
            "ACC1604 gcc Debug LVI" :                                  { ACCTest(AGENTS_LABELS["acc-ubuntu-16.04"], 'gcc', 'Debug', 'ControlFlow', 'ON') },
            "ACC1604 gcc Release LVI" :                                { ACCTest(AGENTS_LABELS["acc-ubuntu-16.04"], 'gcc', 'Release', 'ControlFlow', 'ON') },
            "ACC1604 Container RelWithDebInfo" :                       { ACCContainerTest(AGENTS_LABELS["acc-ubuntu-16.04"], '16.04') },
            "ACC1604 Container RelWithDebInfo LVI" :                   { ACCContainerTest(AGENTS_LABELS["acc-ubuntu-16.04"], '16.04', 'ControlFlow', 'ON') },
            "ACC1604 Package RelWithDebInfo" :                         { ACCPackageTest(AGENTS_LABELS["acc-ubuntu-16.04"], '16.04') },
            "ACC1604 Package RelWithDebInfo LVI" :                     { ACCPackageTest(AGENTS_LABELS["acc-ubuntu-16.04"], '16.04', 'ControlFlow', 'ON') },
            "ACC1804 clang-7 Debug" :                                  { ACCTest(AGENTS_LABELS["acc-ubuntu-18.04"], 'clang-7', 'Debug') },
            "ACC1804 clang-7 Release" :                                { ACCTest(AGENTS_LABELS["acc-ubuntu-18.04"], 'clang-7', 'Release') },
            "ACC1804 clang-7 Debug LVI" :                              { ACCTest(AGENTS_LABELS["acc-ubuntu-18.04"], 'clang-7', 'Debug', 'ControlFlow', 'ON') },
            "ACC1804 clang-7 Release LVI" :                            { ACCTest(AGENTS_LABELS["acc-ubuntu-18.04"], 'clang-7', 'Release', 'ControlFlow', 'ON') },
            "ACC1804 gcc Debug" :                                      { ACCTest(AGENTS_LABELS["acc-ubuntu-18.04"], 'gcc', 'Debug') },
            "ACC1804 gcc Release" :                                    { ACCTest(AGENTS_LABELS["acc-ubuntu-18.04"], 'gcc', 'Release') },
            "ACC1804 gcc Debug LVI" :                                  { ACCTest(AGENTS_LABELS["acc-ubuntu-18.04"], 'gcc', 'Debug', 'ControlFlow', 'ON') },
            "ACC1804 gcc Release LVI" :                                { ACCTest(AGENTS_LABELS["acc-ubuntu-18.04"], 'gcc', 'Release', 'ControlFlow', 'ON') },
            "ACC1804 Container RelWithDebInfo" :                       { ACCContainerTest(AGENTS_LABELS["acc-ubuntu-18.04"], '18.04') },
            "ACC1804 Container RelWithDebInfo LVI" :                   { ACCContainerTest(AGENTS_LABELS["acc-ubuntu-18.04"], '18.04', 'ControlFlow', 'ON') },
            "ACC1804 Package RelWithDebInfo" :                         { ACCPackageTest(AGENTS_LABELS["acc-ubuntu-18.04"], '18.04') },
            "ACC1804 Package RelWithDebInfo LVI" :                     { ACCPackageTest(AGENTS_LABELS["acc-ubuntu-18.04"], '18.04', 'ControlFlow', 'ON') },
            "ACC1804 GNU gcc SGX1FLC" :                                { ACCGNUTest() },
            "AArch64 1604 GNU gcc Debug" :                             { AArch64GNUTest('16.04', 'Debug')},
            "AArch64 1604 GNU gcc Release" :                           { AArch64GNUTest('16.04', 'Release')},
            "AArch64 1804 GNU gcc Debug" :                             { AArch64GNUTest('18.04', 'Debug')},
            "AArch64 1804 GNU gcc Release" :                           { AArch64GNUTest('18.04', 'Release')},
            "Sim 1804 clang-7 SGX1 Debug" :                            { simulationTest('18.04', 'SGX1', 'Debug')},
            "Sim 1804 clang-7 SGX1 Release" :                          { simulationTest('18.04', 'SGX1', 'Release')},
            "Sim 1804 clang-7 SGX1-FLC Debug" :                        { simulationTest('18.04', 'SGX1FLC', 'Debug')},
            "Sim 1804 clang-7 SGX1-FLC Release" :                      { simulationTest('18.04', 'SGX1FLC', 'Release')},
            // "RHEL-8 simulation clang-8 SGX1 Release":             { RHEL8Test('clang', 'Release', ["OE_SIMULATION=1"]) }, // Enable when https://github.com/openenclave/openenclave/issues/2556 is fixed.
            "RHEL-8 simulation clang-8 SGX1 Debug":                    { RHEL8Test('clang', 'Debug',   ["OE_SIMULATION=1"]) },
            // "RHEL-8 simulation gcc-8 Release":                    { RHEL8Test('gcc',   'Release', ["OE_SIMULATION=1"]) }, // Enable when https://github.com/openenclave/openenclave/issues/2558 is fixed.
            "RHEL-8 simulation gcc-8 SGX1 Debug":                      { RHEL8Test('gcc',   'Debug',   ["OE_SIMULATION=1"]) },
            // "RHEL-8 ACC clang-8 Release" :                        { RHEL8Test('clang', 'Release') },                      // Enable when https://github.com/openenclave/openenclave/issues/2556 is fixed.
            // "RHEL-8 ACC clang-8 Debug" :                          { RHEL8Test('clang', 'Debug') },                        // Enable when https://github.com/openenclave/openenclave/issues/2557 is fixed.
            // "RHEL-8 ACC gcc-8 Release" :                          { RHEL8Test('gcc',   'Release') },                      // Enable when https://github.com/openenclave/openenclave/issues/2558 is fixed.
            "RHEL-8 ACC gcc-8 Debug" :                                 { RHEL8Test('gcc',   'Debug') }
} catch(Exception e) {
    println "Caught global pipeline exception :" + e
    GLOBAL_ERROR = e
    throw e
} finally {
    currentBuild.result = (GLOBAL_ERROR != null) ? 'FAILURE' : "SUCCESS"
    oe.emailJobStatus(currentBuild.result)
}
