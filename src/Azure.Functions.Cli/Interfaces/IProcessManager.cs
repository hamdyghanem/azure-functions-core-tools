﻿using System.Collections.Generic;

namespace Azure.Functions.Cli.Interfaces
{
    internal interface IProcessManager
    {
        IEnumerable<IProcessInfo> GetProcessesByName(string processName);
        IProcessInfo GetCurrentProcess();
        IProcessInfo GetProcessById(int processId);
    }
}
