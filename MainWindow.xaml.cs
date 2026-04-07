using System.Text;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
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

    public Visibility EmptyStateVisibility => Certificates.Count == 0 && !IsBusy ? Visibility.Visible : Visibility.Collapsed;

    private async void FetchCertificates_Click(object sender, RoutedEventArgs e)
    {
        if (!TryBuildHttpsUri(UrlInput, out var uri, out var errorMessage))
        {
            StatusMessage = errorMessage;
            return;
        }

        IsBusy = true;
        Certificates.Clear();
        OnPropertyChanged(nameof(EmptyStateVisibility));
        StatusMessage = $"Connecting to {uri.Host}:{uri.Port}...";

        try
        {
            var certificates = await CertificateChainFetcher.FetchAsync(uri);

            for (var i = 0; i < certificates.Count; i++)
            {
                Certificates.Add(new CertificateViewItem(certificates[i], i));
            }

            StatusMessage = Certificates.Count > 0
                ? string.Empty
                : "Connected, but the server did not return a displayable certificate chain.";
        }
        catch (Exception ex)
        {
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
