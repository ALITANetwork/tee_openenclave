// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

"use strict";

export class Constants {

    //
    // Extension details
    //
    public static ExtensionId = "ms-iot.msiot-vscode-openenclave";

    //
    // Github repo and branch for SDK
    //
    public static openEnclaveRepo = "https://github.com/microsoft/openenclave.git";
    public static openEnclaveBranch = "#feature.new_platforms";
    //
    // Azure storage info for DevKit
    //
    public static DevKitBlobAccount = "";
    public static DevKitBlobContainerName = "";
    public static DevKitBlobName = "";

    //
    // Folder and file names
    //
    public static assetsFolder = "assets";
    public static baseSolutionTemplateFolder = "baseSolutionTemplateFolder";
    public static edgeSolutionTemplateFolder = "edgeSolutionTemplateFolder";
    public static standaloneSolutionTemplateFolder = "standaloneSolutionTemplateFolder";
    public static thirdPartyFolder = "3rdparty";
    public static toolchainFolder = "toolchains";
    public static devKitFolder = "devkit";
    public static openEnclaveSdkName = "openenclave";
    public static devKitTarball = "devdata.tar.gz";
    public static configFolder = "config";
    public static configDeploymentFilePattern = "^deployment.(.*).json$";
    public static standaloneBuildFolder = "bld";
    public static edgeModulesFolder = "modules";

    //
    // UI Strings
    //
    public static openEnclaveDisplayName = "Microsoft Open Enclave";
    public static solutionName = "Solution Name";
    public static solutionNamePrompt = "Provide a Solution Name";
    public static edgeSolutionNameDefault = "EdgeOpenEnclave";
    public static standaloneSolutionNameDefault = "OpenEnclave";
    public static selectFolderLabel = "Select Folder";
    public static selectDevKitLabel = "Select DevKit";
    public static noWorkspaceMsg = "This extension only works when folders are opened.";
    public static userCancelled = "Cancelled by user";
    public static standaloneProjectType = "Standalone";
    public static edgeProjectType = "Edge Container";
    public static selectProjectType = "Select Open Enclave solution type";
    public static registryPlaceholder = "<registry>";
    public static repoNamePlaceholder = "<repo-name>";
    public static repositoryPattern = `${Constants.registryPlaceholder}/${Constants.repoNamePlaceholder}`;
    public static providerDockerRepository = "Provide Docker Image Repository for the Open Enclave";
    public static acrEnvSet = "ACR credentials have been set in .env file";
    public static setRegistryEnvNotification = "Please set container registry credentials to .env file";
}
