import React from 'react';
import { AlertTriangle, RotateCcw } from 'lucide-react';

/**
 * Error Boundary Component
 * 
 * Catches rendering errors in child components and displays
 * a user-friendly error UI with recovery options.
 * 
 * Usage:
 * <ErrorBoundary fallback={<ErrorUI />}>
 *   <YourComponent />
 * </ErrorBoundary>
 */
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      errorCount: 0
    };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    console.error('[ErrorBoundary] Caught error:', error, errorInfo);
    
    this.setState(prevState => ({
      error,
      errorInfo,
      errorCount: prevState.errorCount + 1
    }));

    // Log to external service in production
    // logErrorToService(error, errorInfo);
  }

  handleReset = () => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null
    });
  };

  handleRefresh = () => {
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          minHeight: '400px',
          padding: '2rem',
          background: 'rgba(244, 63, 94, 0.05)',
          border: '1px solid rgba(244, 63, 94, 0.2)',
          borderRadius: '20px',
          color: '#f8fafc'
        }}>
          <div style={{ textAlign: 'center', maxWidth: '600px' }}>
            <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '1.5rem' }}>
              <AlertTriangle size={48} color="#f43f5e" />
            </div>
            
            <h3 style={{ fontSize: '1.2rem', fontWeight: 900, marginBottom: '0.5rem' }}>
              Something Went Wrong
            </h3>
            
            <p style={{ fontSize: '0.9rem', color: '#94a3b8', marginBottom: '1.5rem' }}>
              The dashboard encountered an unexpected error. The issue has been logged.
            </p>

            {import.meta.env.MODE === 'development' && (
              <div style={{
                background: 'rgba(0,0,0,0.3)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '12px',
                padding: '1rem',
                marginBottom: '1.5rem',
                textAlign: 'left',
                maxHeight: '200px',
                overflowY: 'auto',
                fontSize: '0.65rem',
                fontFamily: 'monospace',
                color: '#f43f5e'
              }}>
                <div style={{ fontWeight: 800, marginBottom: '0.5rem' }}>Error Details:</div>
                <div>{this.state.error?.toString()}</div>
                {this.state.errorInfo?.componentStack && (
                  <>
                    <div style={{ marginTop: '0.75rem', fontWeight: 800 }}>Stack Trace:</div>
                    <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                      {this.state.errorInfo.componentStack}
                    </pre>
                  </>
                )}
              </div>
            )}

            <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center' }}>
              <button
                onClick={this.handleReset}
                style={{
                  padding: '0.75rem 1.5rem',
                  background: '#38bdf8',
                  color: '#020617',
                  border: 'none',
                  borderRadius: '10px',
                  fontWeight: 800,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  fontSize: '0.9rem'
                }}
              >
                <RotateCcw size={16} /> Try Again
              </button>
              
              <button
                onClick={this.handleRefresh}
                style={{
                  padding: '0.75rem 1.5rem',
                  background: 'rgba(255,255,255,0.1)',
                  color: '#38bdf8',
                  border: '1px solid rgba(56, 189, 248, 0.3)',
                  borderRadius: '10px',
                  fontWeight: 800,
                  cursor: 'pointer',
                  fontSize: '0.9rem'
                }}
              >
                Refresh Page
              </button>
            </div>

            {this.state.errorCount > 3 && (
              <div style={{
                marginTop: '1.5rem',
                padding: '1rem',
                background: 'rgba(245, 158, 11, 0.1)',
                border: '1px solid rgba(245, 158, 11, 0.2)',
                borderRadius: '12px',
                fontSize: '0.75rem',
                color: '#f59e0b'
              }}>
                Multiple errors detected. Please try refreshing the page or contact support if the issue persists.
              </div>
            )}
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
