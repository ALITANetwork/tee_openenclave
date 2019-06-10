@Library("OpenEnclaveCommon") _
oe = new jenkins.common.Openenclave()

// The below timeout is set in minutes
GLOBAL_TIMEOUT = 240
// ctest timeout is set in seconds
CTEST_TIMEOUT = 480

def packageUpload(String version, String build_type) {
    stage("Ubuntu${version} SGX1FLC Package ${build_type}") {
        node("ACC-${version}") {
            timeout(GLOBAL_TIMEOUT) {
                cleanWs()
                checkout scm
                def task = """
                           cmake ${WORKSPACE} -DCMAKE_BUILD_TYPE=${build_type} -DCMAKE_INSTALL_PREFIX:PATH='/opt/openenclave' -DCPACK_GENERATOR=DEB
                           make
                           ctest --output-on-failure --timeout ${CTEST_TIMEOUT}
                           make package
                           """
                oe.Run("clang-7", task)
                azureUpload(storageCredentialId: 'oe_jenkins_storage_account', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: "master/${BUILD_NUMBER}/ubuntu/${version}/${build_type}/SGX1FLC/", containerName: 'oejenkins')
                azureUpload(storageCredentialId: 'oe_jenkins_storage_account', filesPath: 'build/*.deb', storageType: 'blobstorage', virtualPath: "master/latest/ubuntu/${version}/${build_type}/SGX1FLC/", containerName: 'oejenkins')
            }
        }
    }
}

def WindowsUpload() {
    stage('Windows Release') {
        node('SGXFLC-Windows') {
            timeout(GLOBAL_TIMEOUT) {
                cleanWs()
                checkout scm
                dir('build') {
                    bat """vcvars64.bat x64 && \
                           cmake.exe ${WORKSPACE} -G \"Visual Studio 15 2017 Win64\" && \
                           msbuild tools\\oeedger8r\\oeedger8r_target.vcxproj -p:Configuration=Release"""
                }
                azureUpload(storageCredentialId: 'oe_jenkins_storage_account', filesPath: 'build/tools/oeedger8r/oeedger8r.exe', storageType: 'blobstorage', virtualPath: "master/${BUILD_NUMBER}/windows/", containerName: 'oejenkins')
                azureUpload(storageCredentialId: 'oe_jenkins_storage_account', filesPath: 'build/tools/oeedger8r/oeedger8r.exe', storageType: 'blobstorage', virtualPath: "master/latest/windows/", containerName: 'oejenkins')
            }
        }
    }
}

parallel "1604 SGX1FLC Package Debug" :          { packageUpload('1604', 'Debug') },
         "1604 SGX1FLC Package Release" :        { packageUpload('1604', 'Release') },
         "1604 SGX1FLC Package RelWithDebInfo" : { packageUpload('1604', 'RelWithDebInfo') },
         "1804 SGX1FLC Package Debug" :          { packageUpload('1804', 'Debug') },
         "1804 SGX1FLC Package Release" :        { packageUpload('1804', 'Release') },
         "1804 SGX1FLC Package RelWithDebInfo" : { packageUpload('1804', 'RelWithDebInfo') },
         "Windows Release" :                     { WindowsUpload() }
