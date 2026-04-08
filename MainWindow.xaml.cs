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
    private CertificateFetchSource _lastFetchSource;

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
                OnPropertyChanged(nameof(HasValidationError));
            }
        }
    }

    public Visibility EmptyStateVisibility => Certificates.Count == 0 && !IsBusy ? Visibility.Visible : Visibility.Collapsed;

    public bool HasValidationSummary => LastValidationResult is not null;

    public bool IsChainDifferenceReliable => _lastFetchSource == CertificateFetchSource.RawServerSent;

    public string ChainSourceSummary => IsChainDifferenceReliable
        ? "Chain source: raw server-sent certificate message."
        : "Chain source: SslStream fallback. Validated Only and Not Used are hidden for this fetch.";

    public bool HasValidationError => LastValidationResult is not null &&
                                      (!LastValidationResult.IsChainTrusted ||
                                       LastValidationResult.ServerIssues.Any(issue => issue.Severity == ValidationSeverity.Error));

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
        _lastFetchSource = CertificateFetchSource.SslStreamFallback;
        OnPropertyChanged(nameof(EmptyStateVisibility));
        OnPropertyChanged(nameof(IsChainDifferenceReliable));
        StatusMessage = $"Connecting to {uri.Host}:{uri.Port}...";

        try
        {
            var fetchResult = await CertificateChainFetcher.FetchAsync(uri);
            var certificates = fetchResult.Certificates;
            _lastFetchSource = fetchResult.Source;
            OnPropertyChanged(nameof(IsChainDifferenceReliable));
            var validationResult = CertificateValidationService.Validate(uri, certificates);

            for (var i = 0; i < certificates.Count; i++)
            {
                var item = new CertificateViewItem(certificates[i], i, canDisplayChainDiff: IsChainDifferenceReliable);
                var diagnostic = validationResult.CertificateDiagnostics.FirstOrDefault(result =>
                    result.SourceChainIndex == i &&
                    string.Equals(result.Thumbprint, item.Thumbprint, StringComparison.OrdinalIgnoreCase));
                item.ApplyValidationDiagnostic(diagnostic);
                Certificates.Add(item);
            }


            var serverThumbprints = new HashSet<string>(
                certificates
                    .Select(certificate => certificate.Thumbprint)
                    .Where(thumbprint => !string.IsNullOrWhiteSpace(thumbprint))!
                    .Select(thumbprint => thumbprint!),
                StringComparer.OrdinalIgnoreCase);

            foreach (var diagnostic in validationResult.CertificateDiagnostics
                         .Where(result => result.SourceChainIndex < 0)
                         .OrderBy(result => result.RebuiltChainIndex ?? int.MaxValue))
            {
                var rebuiltIndex = diagnostic.RebuiltChainIndex;
                if (rebuiltIndex is null || rebuiltIndex.Value >= validationResult.RebuiltChain.Count)
                {
                    continue;
                }

                var rebuiltCertificate = validationResult.RebuiltChain[rebuiltIndex.Value];
                if (string.IsNullOrWhiteSpace(rebuiltCertificate.Thumbprint) ||
                    !serverThumbprints.Add(rebuiltCertificate.Thumbprint))
                {
                    continue;
                }

                var item = new CertificateViewItem(
                    rebuiltCertificate,
                    Certificates.Count,
                    isServerProvided: false,
                    canDisplayChainDiff: IsChainDifferenceReliable);
                item.ApplyValidationDiagnostic(diagnostic);
                Certificates.Add(item);
            }

            LastValidationResult = validationResult;
            StatusMessage = Certificates.Count > 0
                ? string.Empty
                : "Connected, but the server did not return a displayable certificate chain.";
        }
        catch (Exception ex)
        {
            _lastFetchSource = CertificateFetchSource.SslStreamFallback;
            OnPropertyChanged(nameof(IsChainDifferenceReliable));
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
