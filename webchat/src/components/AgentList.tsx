import React, { useState, useEffect } from 'react';
import type { Agent, AgentPresence } from '../types';
import { getAgents, getPresence } from '../services/api';

interface AgentListProps {
  token: string;
  selectedAgent: string | null;
  onSelectAgent: (agentId: string) => void;
}

export function AgentList({ token, selectedAgent, onSelectAgent }: AgentListProps) {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [presence, setPresence] = useState<Record<string, AgentPresence>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchAgents = async () => {
      try {
        const data = await getAgents(token);
        setAgents(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load agents');
      } finally {
        setLoading(false);
      }
    };
    fetchAgents();
  }, [token]);

  // Poll presence every 15 seconds
  useEffect(() => {
    const fetchPresence = async () => {
      try {
        const data = await getPresence(token);
        const map: Record<string, AgentPresence> = {};
        for (const a of data) {
          map[a.id] = a;
        }
        setPresence(map);
      } catch {
        // Silently ignore presence errors
      }
    };
    fetchPresence();
    const interval = setInterval(fetchPresence, 15000);
    return () => clearInterval(interval);
  }, [token]);

  const getStatusColor = (agentId: string, fallbackStatus: string): string => {
    const p = presence[agentId];
    if (p) {
      if (p.online) return '#3fb950';
      return '#8b949e';
    }
    return fallbackStatus === 'online' ? '#3fb950' :
      fallbackStatus === 'busy' ? '#d29922' : '#8b949e';
  };

  const getStatusLabel = (agentId: string, fallbackStatus: string): string => {
    const p = presence[agentId];
    if (p) return p.online ? 'online' : 'offline';
    return fallbackStatus;
  };

  if (loading) return <div style={styles.loading}>Loading agents...</div>;
  if (error) return <div style={styles.error}>{error}</div>;

  return (
    <div style={styles.container}>
      <h3 style={styles.heading}>Agents</h3>
      {agents.length === 0 && (
        <div style={styles.empty}>No agents online</div>
      )}
      {agents.map((agent) => {
        const statusColor = getStatusColor(agent.id, agent.status);
        const statusLabel = getStatusLabel(agent.id, agent.status);
        return (
          <button
            key={agent.id}
            onClick={() => onSelectAgent(agent.id)}
            style={{
              ...styles.agentCard,
              ...(selectedAgent === agent.id ? styles.agentSelected : {}),
            }}
          >
            <div style={styles.agentHeader}>
              <span style={styles.agentName}>{agent.name || agent.id}</span>
              <div style={styles.statusContainer}>
                <span style={{ ...styles.statusDot, backgroundColor: statusColor }} />
                <span style={{ ...styles.statusLabel, color: statusColor }}>{statusLabel}</span>
              </div>
            </div>
            {agent.specialty && (
              <div style={styles.agentSpecialty}>{agent.specialty}</div>
            )}
            {presence[agent.id]?.last_seen && !presence[agent.id].online && (
              <div style={styles.lastSeen}>
                Last seen {formatLastSeen(presence[agent.id].last_seen!)}
              </div>
            )}
          </button>
        );
      })}
    </div>
  );
}

function formatLastSeen(iso: string): string {
  try {
    const date = new Date(iso);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMin = Math.floor(diffMs / 60000);
    if (diffMin < 1) return 'just now';
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHr = Math.floor(diffMin / 60);
    if (diffHr < 24) return `${diffHr}h ago`;
    const diffDay = Math.floor(diffHr / 24);
    return `${diffDay}d ago`;
  } catch {
    return '';
  }
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    width: '240px',
    backgroundColor: '#161b22',
    borderRight: '1px solid #30363d',
    padding: '1rem',
    overflowY: 'auto',
  },
  heading: {
    fontSize: '0.75rem',
    fontWeight: 600,
    textTransform: 'uppercase' as const,
    color: '#8b949e',
    marginBottom: '0.75rem',
  },
  loading: {
    padding: '1rem',
    color: '#8b949e',
  },
  error: {
    padding: '1rem',
    color: '#f85149',
  },
  empty: {
    padding: '1rem',
    color: '#8b949e',
    fontSize: '0.875rem',
  },
  agentCard: {
    display: 'block',
    width: '100%',
    padding: '0.75rem',
    marginBottom: '0.5rem',
    borderRadius: '6px',
    border: '1px solid #30363d',
    backgroundColor: '#0d1117',
    color: '#e6edf3',
    cursor: 'pointer',
    textAlign: 'left' as const,
  },
  agentSelected: {
    borderColor: '#58a6ff',
    backgroundColor: '#161b22',
  },
  agentHeader: {
    display: 'flex',
    justifyContent: 'space-between' as const,
    alignItems: 'center' as const,
  },
  agentName: {
    fontWeight: 600,
    fontSize: '0.875rem',
  },
  statusContainer: {
    display: 'flex',
    alignItems: 'center' as const,
    gap: '0.25rem',
  },
  statusDot: {
    width: '8px',
    height: '8px',
    borderRadius: '50%',
  },
  statusLabel: {
    fontSize: '0.65rem',
    fontWeight: 500,
  },
  agentSpecialty: {
    fontSize: '0.75rem',
    color: '#8b949e',
    marginTop: '0.25rem',
  },
  lastSeen: {
    fontSize: '0.65rem',
    color: '#6e7681',
    marginTop: '0.125rem',
  },
};