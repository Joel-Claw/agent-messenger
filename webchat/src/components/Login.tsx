import React, { useState } from 'react';
import type { Agent } from '../types';

interface LoginProps {
  onLogin: (token: string, userId: string) => void;
}

export function Login({ onLogin }: LoginProps) {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const { login, register: registerUser } = await import('../services/api');
      if (mode === 'login') {
        const result = await login(username, password);
        onLogin(result.token, result.user_id);
      } else {
        await registerUser(username, password);
        const result = await login(username, password);
        onLogin(result.token, result.user_id);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <h1 style={styles.title}>Agent Messenger</h1>
        <h2 style={styles.subtitle}>
          {mode === 'login' ? 'Sign In' : 'Create Account'}
        </h2>

        {error && <div style={styles.error}>{error}</div>}

        <form onSubmit={handleSubmit} style={styles.form}>
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            style={styles.input}
            required
          />

          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            style={styles.input}
            required
          />

          <button type="submit" style={styles.button} disabled={loading}>
            {loading ? 'Please wait...' : mode === 'login' ? 'Sign In' : 'Create Account'}
          </button>
        </form>

        <p style={styles.switch}>
          {mode === 'login' ? "Don't have an account? " : 'Already have an account? '}
          <button
            style={styles.switchButton}
            onClick={() => { setMode(mode === 'login' ? 'register' : 'login'); setError(''); }}
          >
            {mode === 'login' ? 'Register' : 'Sign In'}
          </button>
        </p>
      </div>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    minHeight: '100vh',
    backgroundColor: '#0d1117',
    color: '#e6edf3',
  },
  card: {
    backgroundColor: '#161b22',
    border: '1px solid #30363d',
    borderRadius: '8px',
    padding: '2rem',
    width: '100%',
    maxWidth: '400px',
  },
  title: {
    fontSize: '1.5rem',
    fontWeight: 600,
    marginBottom: '0.25rem',
    color: '#58a6ff',
  },
  subtitle: {
    fontSize: '1rem',
    fontWeight: 400,
    marginBottom: '1.5rem',
    color: '#8b949e',
  },
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.75rem',
  },
  input: {
    padding: '0.75rem',
    borderRadius: '6px',
    border: '1px solid #30363d',
    backgroundColor: '#0d1117',
    color: '#e6edf3',
    fontSize: '0.875rem',
  },
  button: {
    padding: '0.75rem',
    borderRadius: '6px',
    border: 'none',
    backgroundColor: '#0033AA',
    color: '#ffffff',
    fontSize: '0.875rem',
    fontWeight: 600,
    cursor: 'pointer',
    marginTop: '0.5rem',
  },
  error: {
    backgroundColor: '#3d1216',
    border: '1px solid #b54a4a',
    borderRadius: '6px',
    padding: '0.75rem',
    color: '#f85149',
    fontSize: '0.875rem',
    marginBottom: '0.75rem',
  },
  switch: {
    marginTop: '1rem',
    textAlign: 'center',
    fontSize: '0.875rem',
    color: '#8b949e',
  },
  switchButton: {
    background: 'none',
    border: 'none',
    color: '#58a6ff',
    cursor: 'pointer',
    fontSize: '0.875rem',
    padding: 0,
  },
};