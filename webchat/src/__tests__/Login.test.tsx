import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Login } from '../components/Login';

// Mock the API module
jest.mock('../services/api', () => ({
  login: jest.fn(),
  register: jest.fn(),
}));

import * as api from '../services/api';

const mockLogin = api.login as jest.MockedFunction<typeof api.login>;
const mockRegister = api.register as jest.MockedFunction<typeof api.register>;

describe('Login', () => {
  const mockOnLogin = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders sign in form by default', () => {
    render(<Login onLogin={mockOnLogin} />);
    expect(screen.getByRole('heading', { level: 1, name: 'Agent Messenger' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 2, name: 'Sign In' })).toBeInTheDocument();
    expect(screen.getByLabelText('Username')).toBeInTheDocument();
    expect(screen.getByLabelText('Password')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Sign In' })).toBeInTheDocument();
  });

  it('switches to register mode', () => {
    render(<Login onLogin={mockOnLogin} />);
    const switchBtn = screen.getByRole('button', { name: 'Register' });
    fireEvent.click(switchBtn);
    expect(screen.getByRole('heading', { level: 2, name: 'Create Account' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Create Account' })).toBeInTheDocument();
  });

  it('switches back to login mode', () => {
    render(<Login onLogin={mockOnLogin} />);
    fireEvent.click(screen.getByRole('button', { name: 'Register' }));
    fireEvent.click(screen.getByRole('button', { name: 'Sign In' }));
    expect(screen.getByRole('heading', { level: 2, name: 'Sign In' })).toBeInTheDocument();
  });

  it('calls onLogin on successful login', async () => {
    mockLogin.mockResolvedValueOnce({ token: 'test-token', user_id: 'user123', username: 'testuser' });
    render(<Login onLogin={mockOnLogin} />);

    await userEvent.type(screen.getByLabelText('Username'), 'testuser');
    await userEvent.type(screen.getByLabelText('Password'), 'testpass123');
    fireEvent.submit(screen.getByRole('form'));

    await waitFor(() => {
      expect(mockOnLogin).toHaveBeenCalledWith('test-token', 'user123');
    });
  });

  it('shows error on failed login', async () => {
    mockLogin.mockRejectedValueOnce(new Error('Invalid credentials'));
    render(<Login onLogin={mockOnLogin} />);

    await userEvent.type(screen.getByLabelText('Username'), 'testuser');
    await userEvent.type(screen.getByLabelText('Password'), 'wrongpass');
    fireEvent.submit(screen.getByRole('form'));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('Invalid credentials');
    });
  });

  it('registers then logs in on register mode', async () => {
    mockRegister.mockResolvedValueOnce({ user_id: 'user123', username: 'newuser' });
    mockLogin.mockResolvedValueOnce({ token: 'test-token', user_id: 'user123', username: 'newuser' });

    render(<Login onLogin={mockOnLogin} />);
    fireEvent.click(screen.getByRole('button', { name: 'Register' }));

    await userEvent.type(screen.getByLabelText('Username'), 'newuser');
    await userEvent.type(screen.getByLabelText('Password'), 'testpass123');
    fireEvent.submit(screen.getByRole('form'));

    await waitFor(() => {
      expect(mockRegister).toHaveBeenCalledWith('newuser', 'testpass123');
      expect(mockLogin).toHaveBeenCalledWith('newuser', 'testpass123');
      expect(mockOnLogin).toHaveBeenCalledWith('test-token', 'user123');
    });
  });

  it('shows loading state while submitting', async () => {
    mockLogin.mockImplementationOnce(() => new Promise(() => {}));
    render(<Login onLogin={mockOnLogin} />);

    await userEvent.type(screen.getByLabelText('Username'), 'testuser');
    await userEvent.type(screen.getByLabelText('Password'), 'testpass123');
    fireEvent.submit(screen.getByRole('form'));

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Please wait...' })).toBeInTheDocument();
    });
  });

  it('requires username and password fields', () => {
    render(<Login onLogin={mockOnLogin} />);
    expect(screen.getByLabelText('Username')).toBeRequired();
    expect(screen.getByLabelText('Password')).toBeRequired();
  });

  it('has accessible form labels', () => {
    render(<Login onLogin={mockOnLogin} />);
    expect(screen.getByLabelText('Username')).toBeInTheDocument();
    expect(screen.getByLabelText('Password')).toBeInTheDocument();
  });

  it('clears error when switching modes', () => {
    mockLogin.mockRejectedValueOnce(new Error('Bad creds'));
    render(<Login onLogin={mockOnLogin} />);
    // Switching mode should clear errors
    fireEvent.click(screen.getByRole('button', { name: 'Register' }));
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('has correct form aria-label in login mode', () => {
    render(<Login onLogin={mockOnLogin} />);
    expect(screen.getByRole('form', { name: 'Sign in form' })).toBeInTheDocument();
  });

  it('has correct form aria-label in register mode', () => {
    render(<Login onLogin={mockOnLogin} />);
    fireEvent.click(screen.getByRole('button', { name: 'Register' }));
    expect(screen.getByRole('form', { name: 'Registration form' })).toBeInTheDocument();
  });
});