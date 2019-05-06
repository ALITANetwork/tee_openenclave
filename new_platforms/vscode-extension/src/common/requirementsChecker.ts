// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import { ChildProcess, execSync, ExecSyncOptions, spawn, SpawnOptions } from "child_process";
import * as os from "os";
import * as vscode from "vscode";

export class RequirementsChecker {

    public static async checkRequirements() {

        const promises: Array<Promise<any>> = [];
        const warnings: string[] = [];
        if (os.platform() === "linux") {
            promises.push(this.validateTool("arm-linux-gnueabihf-gcc", ["--version"])
                .catch(async (error) => {
                    warnings.push("Unable to locate GCC (arm-linux-gnueabihf-gcc).");
                }));
            promises.push(this.validateTool("arm-linux-gnueabihf-g++", ["--version"])
                .catch(async (error) => {
                    warnings.push("Unable to locate G++ (arm-linux-gnueabihf-g++).");
                }));
            promises.push(this.validateTool("aarch64-linux-gnu-gcc", ["--version"])
                .catch(async (error) => {
                    warnings.push("Unable to locate GCC (aarch64-linux-gnu-gcc).");
                }));
            promises.push(this.validateTool("aarch64-linux-gnu-g++", ["--version"])
                .catch(async (error) => {
                    warnings.push("Unable to locate G++ (aarch64-linux-gnu-g++).");
                }));
            promises.push(this.validateTool("gdb-multiarch", ["--version"])
                .catch(async (error) => {
                    warnings.push("Unable to locate GDB (gdb-multiarch).");
                }));
            promises.push(this.validateTool("python", ["--version"])
                .catch(async (error) => {
                    warnings.push("Unable to locate PYTHON.");
                }));
        } else if (os.platform() === "win32") {
            promises.push(this.validateTool("git", ["config", "--get", "--system", "core.longpaths"])
                .then(async (output) => {
                    if (!output || !(/^true/.test(output.trim().toLowerCase()))) {
                        warnings.push(`Enable long paths for GIT.`);
                    }
                })
                .catch(async (error) => {
                    warnings.push(`Enable long paths for GIT.`);
                }));
        }
        promises.push(this.validateTool("docker", ["--version"])
            .catch(async (error) => {
                warnings.push("Unable to locate DOCKER.");
            }));
        promises.push(this.validateTool("git", ["--version"])
            .catch(async (error) => {
                warnings.push("Unable to locate GIT.");
            }));
        promises.push(this.validateTool("cmake", ["--version"])
            .then(async (output) => {
                const versionLine = output.split("\n").filter((line) => line.indexOf("cmake version") !== -1);
                if (versionLine && versionLine.length > 0) {
                    const versionMatches = versionLine[0].match(/^cmake version ([0-9]+)\.([0-9]+)\.([0-9]+)$/);
                    if (versionMatches && versionMatches.length === 4) {
                        const major = parseInt(versionMatches[1], 10);
                        const minor = parseInt(versionMatches[2], 10);
                        if (major < 3 || (major === 3 && minor < 12)) {
                            warnings.push(`Incorrect CMAKE found (${major}.${minor}).  Version 3.12.0 or higher is required.`);
                        }
                    }
                }
            })
            .catch(async (error) => {
                warnings.push("Unable to locate CMAKE 3.12 or higher.");
            }));
        await Promise.all(promises)
            .then(async () => {
                if (warnings.length !== 0) {
                    await this.showWarning(warnings.join("  "));
                }
            });
    }

    private static async showWarning(message: string) {
        const requirementsLink = "https://marketplace.visualstudio.com/items?itemName=ms-iot.msiot-vscode-openenclave";
        const learnMore: vscode.MessageItem = { title: "Learn more" };

        if (await vscode.window.showWarningMessage(`Some requirements are not found.  ${message}  Click Learn more button to see requirements.` , ...[learnMore]) === learnMore) {
            await vscode.commands.executeCommand("vscode.open", vscode.Uri.parse(requirementsLink));
        }
    }

    private static validateTool(command: string, args: string[]): Promise<string> {

        return new Promise(async (resolve, reject) => {

            let stderr: string = "";
            let stdOutput: string = "";

            const p: ChildProcess = spawn(command, args, {shell: true});
            p.stdout.on("data", (data: string | Buffer): void => {
                const dataStr = data.toString();
                stdOutput = stdOutput.concat(dataStr);
            });
            p.stderr.on("data", (data: string | Buffer) => {
                const dataStr = data.toString();
                stderr = stderr.concat(dataStr);
            });
            p.on("error", (err: Error) => {
                reject(new Error(`${err.toString()}. Detail: ${stderr}`));
            });
            p.on("exit", (code: number, signal: string) => {
                if (code !== 0) {
                    reject (new Error((`Command failed with exit code ${code}. Detail: ${stderr}`)));
                } else {
                    resolve(stdOutput);
                }
            });
        });
    }
}
