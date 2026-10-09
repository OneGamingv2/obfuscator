using System.Windows;

namespace OneGamingOBFUSCATION;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        if (e.Args.Length > 0)
        {
            var code = Cli.Run(e.Args);
            Shutdown(code);
            return;
        }

        base.OnStartup(e);
        new MainWindow().Show();
    }
}
