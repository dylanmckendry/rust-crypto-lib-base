using System.Reflection;
using System.Runtime.InteropServices;

namespace Slipstream.CommonDotNet.ExtendedSigner
{
    public static unsafe partial class ExtendedSigner
    {
        static ExtendedSigner()
        {
            NativeLibrary.SetDllImportResolver(typeof(ExtendedSigner).Assembly, DllImportResolver);
        }

        static IntPtr DllImportResolver(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
        {
            if (libraryName == __DllName)
            {
                var path = "runtimes/";
                var prefix = string.Empty;
                string extension;

                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    path += "win-";
                    extension = ".dll";
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    path += "osx-";
                    extension = ".dylib";
                }
                else
                {
                    path += "linux-";
                    prefix = "lib";
                    extension = ".so";
                }

                if (RuntimeInformation.ProcessArchitecture == Architecture.X86)
                {
                    path += "x86";
                }
                else if (RuntimeInformation.ProcessArchitecture == Architecture.X64)
                {
                    path += "x64";
                }
                else if (RuntimeInformation.ProcessArchitecture == Architecture.Arm64)
                {
                    path += "arm64";
                }

                var fileName = prefix + __DllName + extension;

                var runtimePublishFile = Path.Combine(AppContext.BaseDirectory, fileName);
                if (File.Exists(runtimePublishFile))
                {
                    return NativeLibrary.Load(runtimePublishFile, assembly, searchPath);
                }

                return NativeLibrary.Load(Path.Combine(AppContext.BaseDirectory, path + "/native/" + fileName), assembly, searchPath);
            }

            return IntPtr.Zero;
        }
    }
}
