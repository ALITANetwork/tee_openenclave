﻿using System;
using System.Collections.Generic;
using Microsoft.VisualStudio.TemplateWizard;
using System.Windows.Forms;
using EnvDTE;
using System.IO;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using Microsoft.VisualStudio;

namespace OpenEnclaveSDK
{
    public class WizardImplementation : IWizard
    {
        public static string EdlLocation;

        // This method is called before opening any item that   
        // has the OpenInEditor attribute.  
        public void BeforeOpeningFile(ProjectItem projectItem)
        {
        }

        public void ProjectFinishedGenerating(Project project)
        {
        }

        // This method is only called for item templates, not for project templates.  
        public void ProjectItemFinishedGenerating(ProjectItem projectItem)
        {
        }

        // This method is called after the project is created.  
        public void RunFinished()
        {
        }

        // Look in <folder>/conf.mk to see what is supported.
        private void GetConfFlags(string folder, out bool hardwareFloatSupported, out bool is32Bit)
        {
            ThreadHelper.ThrowIfNotOnUIThread();

            // Set default values.
            hardwareFloatSupported = false;
            is32Bit = false;

            try
            {
                string fileName = Path.Combine(folder, "mk\\conf.mk");
                var lines = File.ReadLines(fileName);
                foreach (var line in lines)
                {
                    string trimmed = line.Trim();
                    string token = trimmed.Split(' ', ':', '?')[0];

                    if (token == "CFG_TA_FLOAT_SUPPORT")
                    {
                        // "CFG_TA_FLOAT_SUPPORT := y" means hardware float support is enabled.
                        hardwareFloatSupported = trimmed.EndsWith("y");
                    }
                    else if (token == "sm")
                    {
                        // "sm := ta_arm32" means 32-bit.
                        is32Bit = trimmed.EndsWith("ta_arm32");
                    }
                }
            }
            catch (IOException e)
            {
                // Output a warning so the developer knows they won't get hardware float support.
                IVsOutputWindow outWindow = Package.GetGlobalService(typeof(SVsOutputWindow)) as IVsOutputWindow;
                Guid generalPaneGuid = VSConstants.GUID_OutWindowGeneralPane;
                IVsOutputWindowPane generalPane;
                outWindow.GetPane(ref generalPaneGuid, out generalPane);
                if (generalPane == null)
                {
                    // The General pane isn't there yet, so create it.
                    string customTitle = "General";
                    outWindow.CreatePane(ref generalPaneGuid, customTitle, 1, 1);
                    outWindow.GetPane(ref generalPaneGuid, out generalPane);
                }
                if (generalPane != null)
                {
                    generalPane.OutputString("Warning: No hardware float support detected, using software support instead");
                    generalPane.Activate(); // Bring the pane into view.
                }
            }
        }

        // Convert a path in Windows format to a path in WSL format.
        private string GetUnixPath(string folder)
        {
            string root = Path.GetPathRoot(folder).ToLower();
            string relativeFolder = folder.Substring(root.Length).Replace('\\', '/');
            string drive = root.Substring(0, 1);
            string unixPath = "/mnt/" + drive + "/" + relativeFolder;
            return unixPath;
        }

        // Set the path to the OpenEnclave libs and TA Dev Kit.
        private bool SetOELibPath(Dictionary<string, string> replacementsDictionary)
        {
            // First try picking the board from a menu.
            BoardPickerPage picker = new BoardPickerPage();
            DialogResult result = picker.ShowDialog();
            if (result != DialogResult.OK || picker.Board == "None")
            {
                // No ARM support requested.
                return false;
            }

            string oeFolder = null;
            string board = picker.Board;
            if (board != "Other")
            {
                // User picked a specific board for which we have binaries in the nuget package.
                string solutionDirectory;
                replacementsDictionary.TryGetValue("$solutiondirectory$", out solutionDirectory);
                oeFolder = Path.Combine(solutionDirectory, "packages\\openenclave.0.2.0-CI-20190521-020719\\lib\\native\\gcc6\\optee\\v3.3.0\\" + board);
            }
            else
            {
                // Ok, the user picked "Other", so ask the user for their own Open Enclave build location.
                using (OpenFileDialog openFileDialog = new OpenFileDialog())
                {
                    openFileDialog.Title = "Select the path to the liboeenclave.a in your Open Enclave build output directory, or hit Cancel to skip ARM support";
                    openFileDialog.InitialDirectory = Directory.GetCurrentDirectory(); // Must be an absolute path.
                    openFileDialog.Filter = "liboeenclave.a|liboeenclave.a";
                    openFileDialog.RestoreDirectory = true;

                    if (openFileDialog.ShowDialog() != DialogResult.OK)
                    {
                        return false;
                    }

                    // Get the path of specified file.
                    string filePath = openFileDialog.FileName;
                    oeFolder = Path.GetFullPath(Path.Combine(filePath, ".."));
                }
            }
            replacementsDictionary.Add("$OELibPath$", GetUnixPath(oeFolder));

            // Now get the path to the associated TA Dev Kit, which should be under
            // devkit or export-ta_arm64 or export-ta_arm32.
            string taDevKitFolder = Path.Combine(oeFolder, "devkit");
            if (!Directory.Exists(taDevKitFolder))
            {
                taDevKitFolder = Path.Combine(oeFolder, "export-ta_arm64");
            }
            if (!Directory.Exists(taDevKitFolder))
            {
                taDevKitFolder = Path.Combine(oeFolder, "export-ta_arm32");
            }
            replacementsDictionary.Add("$OETADevKitPath$", GetUnixPath(taDevKitFolder));

            bool hardwareFloatSupported;
            bool is32Bit;
            GetConfFlags(taDevKitFolder, out hardwareFloatSupported, out is32Bit);

            string opteeCompilerFlavor;
            if (!is32Bit)
            {
                opteeCompilerFlavor = "aarch64-linux-gnu-";
            }
            else
            {
                if (hardwareFloatSupported)
                {
                    opteeCompilerFlavor = "arm-linux-gnueabihf-";
                }
                else
                {
                    opteeCompilerFlavor = "arm-linux-gnueabi-";
                }
            }
            replacementsDictionary.Add("$OpteeCompilerFlavor$", opteeCompilerFlavor);

            return true;
        }

        private bool SetEnclaveName(Dictionary<string, string> replacementsDictionary)
        {
            try
            {
                string safeitemname;
                replacementsDictionary.TryGetValue("$safeitemname$", out safeitemname);

                // Extract enclave name.
                if (safeitemname.EndsWith("_host") && (safeitemname.Length > 5))
                {
                    string enclavename = safeitemname.Substring(0, safeitemname.Length - 5);

                    // Add $enclavename$.
                    replacementsDictionary.Add("$enclavename$", enclavename);
                }

                // Try to get enclave guid from the enclave project.
                string enclaveguid = "FILL THIS IN";
                string makFileName = Path.Combine(EdlLocation, "optee", "linux_gcc.mak");
                foreach (string line in File.ReadLines(makFileName))
                {
                    int index = line.IndexOf("BINARY=");
                    if (index >= 0)
                    {
                        enclaveguid = line.Substring(index + 7).Trim();
                        break;
                    }
                }
                replacementsDictionary.Add("$enclaveguid$", enclaveguid);

                return true;
            }
            catch (Exception)
            {

            }
            return false;
        }

        public void RunStarted(
            object automationObject,
            Dictionary<string, string> replacementsDictionary,
            WizardRunKind runKind,
            object[] customParams)
        {
            try
            {
                // Get the $guid1$ value that has already been generated, and
                // create a struct version of it for use in code that needs it.
                string guid1;
                replacementsDictionary.TryGetValue("$guid1$", out guid1);

                /* Add $guid1struct$ */
                Guid guid1binary = Guid.Parse(guid1);
                string guid1struct = guid1binary.ToString("X");
                replacementsDictionary.Add("$guid1struct$", guid1struct);

                if (runKind == WizardRunKind.AsNewItem)
                {
                    SetEnclaveName(replacementsDictionary);
                }
                else
                {
                    SetOELibPath(replacementsDictionary);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }

        // This method is only called for item templates, not for project templates.  
        public bool ShouldAddProjectItem(string filePath)
        {
            return true;
        }
    }
}
