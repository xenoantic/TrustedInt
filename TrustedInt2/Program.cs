using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TrustedInt
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string commandLine = "cmd.exe";

            // Start the TrustedInstaller service and create a process with TrustedInstaller privileges
            if (!Functions.CheckIfAdmin())
            {
                Console.WriteLine("User is not an Administrator.");
                return;
            }

            int pid = Functions.StartTrustedInstallerService();
            Functions.CreateProcessAsTrustedInstaller(pid, commandLine);
        }
    }
}
