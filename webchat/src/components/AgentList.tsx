import React, { useState, useEffect, useRef } from 'react';
import type { Agent } from '../types';
import { getAgents } from '../services/api';

interface AgentListProps {
  token: string;
  selectedAgent: string | null;
  onSelectAgent: (agentId: string) => void;
}

export function AgentList({ token, selectedAgent, onSelectAgent }: AgentListProps) {
  const [agents, setAgents] = useState<Agent[]>([]);
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

  if (loading) return <div style={styles.loading}>Loading agents...</div>;
  if (error) return <div style={styles.error}>{error}</div>;

  return (
    <div style={styles.container}>
      <h3 style={styles.heading}>Agents</h3>
      {agents.length === 0 && (
        <div style={styles.empty}>No agents online</div>
      )}
      {agents.map((agent) => (
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
            <span style={{
              ...styles.statusDot,
              backgroundColor: agent.status === 'online' ? '#3fb950' :
                agent.status === 'busy' ? '#d29922' : '#8b949e',
            }} />
          </div>
          {agent.specialty && (
            <div style={styles.agentSpecialty}>{agent.specialty}</div>
          )}
        </button>
      ))}
    </div>
  );
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
  statusDot: {
    width: '8px',
    height: '8px',
    borderRadius: '50%',
  },
  agentSpecialty: {
    fontSize: '0.75rem',
    color: '#8b949e',
    marginTop: '0.25rem',
  },
};