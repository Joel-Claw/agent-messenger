import React, { useState, useEffect } from 'react';
import {
  initializeE2E,
  isE2EInitialized,
  resetE2E,
  getLocalIdentityKey,
} from '../services/e2e';

interface E2ESettingsProps {
  token: string;
  onClose: () => void;
}

export function E2ESettings({ token, onClose }: E2ESettingsProps) {
  const [initialized, setInitialized] = useState(isE2EInitialized());
  const [publicKey, setPublicKey] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  useEffect(() => {
    if (initialized) {
      getLocalIdentityKey().then(key => {
        if (key) setPublicKey(key.publicKeyB64);
      });
    }
  }, [initialized]);

  const handleInitialize = async () => {
    setLoading(true);
    setError(null);
    setSuccess(null);
    try {
      await initializeE2E(token);
      setInitialized(true);
      const key = await getLocalIdentityKey();
      if (key) setPublicKey(key.publicKeyB64);
      setSuccess('E2E encryption initialized! Your identity key has been generated and uploaded.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to initialize E2E');
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    if (!window.confirm('Reset E2E keys? You will need to re-establish sessions with all contacts. Encrypted messages from before will become unreadable.')) {
      return;
    }
    resetE2E();
    setInitialized(false);
    setPublicKey('');
    setSuccess(null);
    setError(null);
  };

  const handleCopyKey = () => {
    navigator.clipboard.writeText(publicKey).then(() => {
      setSuccess('Public key copied to clipboard!');
      setTimeout(() => setSuccess(null), 2000);
    });
  };

  return (
    <div style={styles.overlay}>
      <div style={styles.panel}>
        <div style={styles.header}>
          <span style={styles.title}>🔒 End-to-End Encryption</span>
          <button onClick={onClose} style={styles.closeButton}>×</button>
        </div>

        <div style={styles.body}>
          {!initialized ? (
            <div style={styles.setupSection}>
              <div style={styles.description}>
                Generate an X25519 identity key pair to enable end-to-end encrypted messaging.
                Your public key will be uploaded to the server for key exchange.
                The server never sees your private key or message plaintext.
              </div>
              <div style={styles.howItWorks}>
                <div style={styles.howTitle}>How it works</div>
                <ol style={styles.stepList}>
                  <li>A X25519 identity key pair is generated in your browser</li>
                  <li>Your public key is uploaded for key exchange</li>
                  <li>When chatting with an E2E-enabled contact, a shared secret is derived (X3DH)</li>
                  <li>Messages are encrypted with AES-256-GCM before leaving your browser</li>
                  <li>Only you and your contact can decrypt messages</li>
                </ol>
              </div>
              <button
                onClick={handleInitialize}
                disabled={loading}
                style={{
                  ...styles.initButton,
                  opacity: loading ? 0.6 : 1,
                }}
              >
                {loading ? '⏳ Generating keys...' : '🔐 Generate E2E Keys'}
              </button>
            </div>
          ) : (
            <div style={styles.activeSection}>
              <div style={styles.statusBadge}>
                <span style={styles.statusDot}>●</span>
                E2E Encryption Active
              </div>

              <div style={styles.keySection}>
                <div style={styles.keyLabel}>Your Identity Public Key (X25519)</div>
                <div style={styles.keyDisplay}>
                  <code style={styles.keyText}>
                    {publicKey ? `${publicKey.slice(0, 20)}...${publicKey.slice(-12)}` : 'Loading...'}
                  </code>
                  <button onClick={handleCopyKey} style={styles.copyButton} title="Copy full key">
                    📋
                  </button>
                </div>
              </div>

              <div style={styles.infoBox}>
                <strong>Note:</strong> Your private key is stored only in this browser's localStorage.
                Clearing browser data will delete it. Encrypted messages can only be decrypted
                with the matching private key.
              </div>

              <button onClick={handleReset} style={styles.resetButton}>
                🔄 Reset E2E Keys
              </button>
            </div>
          )}

          {error && <div style={styles.error}>{error}</div>}
          {success && <div style={styles.success}>{success}</div>}
        </div>
      </div>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  overlay: {
    position: 'fixed' as const,
    inset: 0,
    backgroundColor: 'rgba(0, 0, 0, 0.6)',
    display: 'flex',
    justifyContent: 'center' as const,
    alignItems: 'center' as const,
    zIndex: 100,
  },
  panel: {
    backgroundColor: '#161b22',
    borderRadius: '12px',
    border: '1px solid #30363d',
    width: '480px',
    maxWidth: '90vw',
    maxHeight: '80vh',
    overflowY: 'auto' as const,
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between' as const,
    alignItems: 'center' as const,
    padding: '1rem 1.25rem',
    borderBottom: '1px solid #30363d',
  },
  title: {
    fontWeight: 600,
    fontSize: '1rem',
    color: '#e6edf3',
  },
  closeButton: {
    background: 'none',
    border: 'none',
    color: '#8b949e',
    fontSize: '1.25rem',
    cursor: 'pointer',
    padding: '0.25rem',
  },
  body: {
    padding: '1.25rem',
  },
  setupSection: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '1rem',
  },
  description: {
    fontSize: '0.875rem',
    color: '#8b949e',
    lineHeight: 1.6,
  },
  howItWorks: {
    backgroundColor: '#0d1117',
    borderRadius: '8px',
    padding: '0.75rem 1rem',
    border: '1px solid #21262d',
  },
  howTitle: {
    fontWeight: 600,
    fontSize: '0.8rem',
    color: '#58a6ff',
    marginBottom: '0.5rem',
    textTransform: 'uppercase' as const,
    letterSpacing: '0.5px',
  },
  stepList: {
    margin: 0,
    paddingLeft: '1.25rem',
    fontSize: '0.8rem',
    color: '#8b949e',
    lineHeight: 1.8,
  },
  initButton: {
    padding: '0.75rem 1.5rem',
    borderRadius: '8px',
    border: 'none',
    backgroundColor: '#238636',
    color: '#ffffff',
    fontWeight: 600,
    cursor: 'pointer',
    fontSize: '0.875rem',
    alignSelf: 'flex-start' as const,
  },
  activeSection: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '1rem',
  },
  statusBadge: {
    display: 'flex',
    alignItems: 'center' as const,
    gap: '0.5rem',
    fontSize: '0.875rem',
    color: '#3fb950',
    fontWeight: 500,
  },
  statusDot: {
    fontSize: '0.75rem',
  },
  keySection: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '0.375rem',
  },
  keyLabel: {
    fontSize: '0.75rem',
    color: '#8b949e',
    fontWeight: 500,
  },
  keyDisplay: {
    display: 'flex',
    alignItems: 'center' as const,
    gap: '0.5rem',
    backgroundColor: '#0d1117',
    borderRadius: '6px',
    padding: '0.5rem 0.75rem',
    border: '1px solid #21262d',
  },
  keyText: {
    fontSize: '0.75rem',
    color: '#58a6ff',
    fontFamily: 'monospace',
    flex: 1,
    overflow: 'hidden',
    textOverflow: 'ellipsis' as const,
    whiteSpace: 'nowrap' as const,
  },
  copyButton: {
    background: 'none',
    border: 'none',
    cursor: 'pointer',
    fontSize: '0.875rem',
    padding: '0.25rem',
  },
  infoBox: {
    fontSize: '0.75rem',
    color: '#8b949e',
    lineHeight: 1.6,
    padding: '0.75rem',
    backgroundColor: 'rgba(88, 166, 255, 0.05)',
    borderRadius: '6px',
    border: '1px solid rgba(88, 166, 255, 0.15)',
  },
  resetButton: {
    padding: '0.5rem 1rem',
    borderRadius: '6px',
    border: '1px solid #f85149',
    backgroundColor: 'transparent',
    color: '#f85149',
    cursor: 'pointer',
    fontSize: '0.8rem',
    alignSelf: 'flex-start' as const,
  },
  error: {
    fontSize: '0.8rem',
    color: '#f85149',
    padding: '0.5rem 0.75rem',
    backgroundColor: 'rgba(248, 81, 73, 0.1)',
    borderRadius: '6px',
  },
  success: {
    fontSize: '0.8rem',
    color: '#3fb950',
    padding: '0.5rem 0.75rem',
    backgroundColor: 'rgba(63, 185, 80, 0.1)',
    borderRadius: '6px',
  },
};