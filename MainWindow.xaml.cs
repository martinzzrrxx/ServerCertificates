using System.Text;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows;
using ServerCertViewer.Models;
using ServerCertViewer.Services;

namespace ServerCertViewer;

public partial class MainWindow : Window, INotifyPropertyChanged
{
    private string _urlInput = "https://example.com";
    private string _statusMessage = string.Empty;
    private bool _isBusy;
    private ServerCertificateValidationResult? _lastValidationResult;

    public MainWindow()
    {
        InitializeComponent();
        DataContext = this;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<CertificateViewItem> Certificates { get; } = [];

    public string UrlInput
    {
        get => _urlInput;
        set => SetField(ref _urlInput, value);
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set => SetField(ref _statusMessage, value);
    }

    public bool IsBusy
    {
        get => _isBusy;
        set
        {
            if (SetField(ref _isBusy, value))
            {
                OnPropertyChanged(nameof(EmptyStateVisibility));
            }
        }
    }

    public ServerCertificateValidationResult? LastValidationResult
    {
        get => _lastValidationResult;
        private set
        {
            if (SetField(ref _lastValidationResult, value))
            {
                OnPropertyChanged(nameof(HasValidationSummary));
                OnPropertyChanged(nameof(OverallValidationLabel));
                OnPropertyChanged(nameof(HostnameValidationLabel));
                OnPropertyChanged(nameof(ChainTrustLabel));
                OnPropertyChanged(nameof(ServerIssuesLabel));
            }
        }
    }

    public Visibility EmptyStateVisibility => Certificates.Count == 0 && !IsBusy ? Visibility.Visible : Visibility.Collapsed;

    public bool HasValidationSummary => LastValidationResult is not null;

    public string OverallValidationLabel => LastValidationResult is null
        ? "Not evaluated"
        : LastValidationResult.ServerIssues.Any(issue => issue.Severity == ValidationSeverity.Error)
            ? "Failed"
            : LastValidationResult.ServerIssues.Any(issue => issue.Severity == ValidationSeverity.Warning)
                ? "Warning"
                : "Passed";

    public string HostnameValidationLabel => LastValidationResult is null
        ? "Not evaluated"
        : LastValidationResult.IsHostnameMatch ? "Passed" : "Failed";

    public string ChainTrustLabel => LastValidationResult is null
        ? "Not evaluated"
        : LastValidationResult.IsChainTrusted ? "Passed" : "Failed";

    public string ServerIssuesLabel => LastValidationResult is null
        ? "No validation results yet"
        : $"{LastValidationResult.ServerIssues.Count} server-level issue(s)";

    private async void FetchCertificates_Click(object sender, RoutedEventArgs e)
    {
        if (!TryBuildHttpsUri(UrlInput, out var uri, out var errorMessage))
        {
            StatusMessage = errorMessage;
            return;
        }

        IsBusy = true;
        Certificates.Clear();
        LastValidationResult = null;
        OnPropertyChanged(nameof(EmptyStateVisibility));
        StatusMessage = $"Connecting to {uri.Host}:{uri.Port}...";

        try
        {
            var certificates = await CertificateChainFetcher.FetchAsync(uri);
            var validationResult = CertificateValidationService.Validate(uri, certificates);

            for (var i = 0; i < certificates.Count; i++)
            {
                var item = new CertificateViewItem(certificates[i], i);
                var diagnostic = validationResult.CertificateDiagnostics.FirstOrDefault(result =>
                    result.SourceChainIndex == i &&
                    string.Equals(result.Thumbprint, item.Thumbprint, StringComparison.OrdinalIgnoreCase));
                item.ApplyValidationDiagnostic(diagnostic);
                Certificates.Add(item);
            }

            LastValidationResult = validationResult;
            StatusMessage = Certificates.Count > 0
                ? BuildValidationSummary(validationResult)
                : "Connected, but the server did not return a displayable certificate chain.";
        }
        catch (Exception ex)
        {
            LastValidationResult = null;
            StatusMessage = $"Fetch failed: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
            OnPropertyChanged(nameof(EmptyStateVisibility));
        }
    }

    private static bool TryBuildHttpsUri(string input, out Uri uri, out string errorMessage)
    {
        uri = null!;
        errorMessage = string.Empty;

        var normalized = string.IsNullOrWhiteSpace(input) ? string.Empty : input.Trim();
        if (string.IsNullOrWhiteSpace(normalized))
        {
            errorMessage = "Please enter an HTTPS URL.";
            return false;
        }

        if (!normalized.Contains("://", StringComparison.Ordinal))
        {
            normalized = $"https://{normalized}";
        }

        if (!Uri.TryCreate(normalized, UriKind.Absolute, out var parsedUri))
        {
            errorMessage = "The URL format is invalid.";
            return false;
        }

        uri = parsedUri;

        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            errorMessage = "Only HTTPS URLs are supported.";
            return false;
        }

        return true;
    }

    private static string BuildValidationSummary(ServerCertificateValidationResult validationResult)
    {
        var issues = validationResult.ServerIssues.Count;
        var trustText = validationResult.IsChainTrusted ? "trusted" : "not trusted";
        var hostnameText = validationResult.IsHostnameMatch ? "hostname matched" : "hostname mismatch";
        return $"Validation complete: chain {trustText}, {hostnameText}, {issues} server-level issue(s).";
    }

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
