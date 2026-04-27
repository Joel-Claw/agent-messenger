import React, { useState, useRef, useEffect } from 'react';
import { uploadAttachment, formatFileSize } from '../services/api';
import type { UploadResult, UploadStatus } from '../types';

interface AttachmentUploadProps {
  token: string;
  onUploaded: (result: UploadResult) => void;
  disabled?: boolean;
  droppedFiles?: File[] | null;
  onDropsConsumed?: () => void;
}

interface PendingFile {
  file: File;
  status: UploadStatus;
  progress: number;
  result?: UploadResult;
  error?: string;
}

export function AttachmentUpload({ token, onUploaded, disabled, droppedFiles, onDropsConsumed }: AttachmentUploadProps) {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [pending, setPending] = useState<PendingFile[]>([]);

  // Handle dropped files from parent drag-and-drop
  useEffect(() => {
    if (droppedFiles && droppedFiles.length > 0) {
      uploadFiles(droppedFiles);
      onDropsConsumed?.();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [droppedFiles]);

  const uploadFiles = async (files: File[]) => {
    const newPending: PendingFile[] = files.map(file => ({
      file,
      status: 'uploading' as UploadStatus,
      progress: 0,
    }));

    setPending(prev => [...prev, ...newPending]);

    for (const pf of newPending) {
      try {
        const result = await uploadAttachment(token, pf.file, (percent) => {
          setPending(prev => {
            const updated = [...prev];
            const idx = prev.findIndex(p => p.file === pf.file);
            if (idx >= 0) {
              updated[idx] = { ...updated[idx], progress: percent };
            }
            return updated;
          });
        });

        setPending(prev => {
          const updated = [...prev];
          const idx = prev.findIndex(p => p.file === pf.file);
          if (idx >= 0) {
            updated[idx] = { ...updated[idx], status: 'done', result };
          }
          return updated;
        });

        onUploaded(result);
      } catch (err) {
        setPending(prev => {
          const updated = [...prev];
          const idx = prev.findIndex(p => p.file === pf.file);
          if (idx >= 0) {
            updated[idx] = {
              ...updated[idx],
              status: 'error',
              error: err instanceof Error ? err.message : 'Upload failed',
            };
          }
          return updated;
        });
      }
    }

    // Clear completed/error items after 3 seconds
    setTimeout(() => {
      setPending(prev => prev.filter(p => p.status === 'uploading'));
    }, 3000);
  };

  const handleClick = () => {
    fileInputRef.current?.click();
  };

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;
    await uploadFiles(Array.from(files));
    // Reset file input
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleRemove = (pf: PendingFile) => {
    setPending(prev => prev.filter(p => p.file !== pf.file));
  };

  return (
    <div style={styles.container}>
      <input
        ref={fileInputRef}
        type="file"
        multiple
        onChange={handleFileSelect}
        style={styles.hiddenInput}
        accept="image/*,audio/*,video/*,.pdf,.txt,.csv,.md,.json"
        data-attach-input
      />
      <button
        type="button"
        onClick={handleClick}
        disabled={disabled}
        style={{
          ...styles.attachButton,
          opacity: disabled ? 0.4 : 1,
        }}
        title="Attach file"
        aria-label="Attach file"
      >
        📎
      </button>
      {pending.length > 0 && (
        <div style={styles.pendingList}>
          {pending.map((pf, i) => (
            <div key={i} style={styles.pendingItem}>
              <span style={styles.pendingIcon}>
                {pf.status === 'uploading' && '⏳'}
                {pf.status === 'done' && '✅'}
                {pf.status === 'error' && '❌'}
              </span>
              <span style={styles.pendingName} title={pf.file.name}>
                {pf.file.name.length > 16 ? pf.file.name.slice(0, 14) + '…' : pf.file.name}
              </span>
              <span style={styles.pendingSize}>
                {formatFileSize(pf.file.size)}
              </span>
              {pf.status === 'uploading' && (
                <div style={styles.progressBar}>
                  <div style={{ ...styles.progressFill, width: `${pf.progress}%` }} />
                </div>
              )}
              {pf.status === 'error' && (
                <span style={styles.pendingError} title={pf.error}>
                  failed
                </span>
              )}
              {pf.status !== 'uploading' && (
                <button
                  type="button"
                  onClick={() => handleRemove(pf)}
                  style={styles.removeButton}
                  aria-label="Remove"
                >
                  ×
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'flex-start',
  },
  hiddenInput: {
    display: 'none',
  },
  attachButton: {
    background: 'none',
    border: 'none',
    color: '#8b949e',
    fontSize: '1.25rem',
    cursor: 'pointer',
    padding: '0.25rem 0.5rem',
    borderRadius: '4px',
    transition: 'color 0.15s',
  },
  pendingList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.25rem',
    marginTop: '0.25rem',
    maxWidth: '240px',
  },
  pendingItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.25rem',
    fontSize: '0.75rem',
    color: '#8b949e',
    padding: '0.25rem 0.5rem',
    backgroundColor: '#21262d',
    borderRadius: '4px',
    flexWrap: 'wrap',
  },
  pendingIcon: {
    fontSize: '0.7rem',
  },
  pendingName: {
    maxWidth: '100px',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap' as const,
  },
  pendingSize: {
    color: '#6e7681',
  },
  progressBar: {
    flex: '1 1 100%',
    height: '3px',
    backgroundColor: '#30363d',
    borderRadius: '2px',
    overflow: 'hidden',
  },
  progressFill: {
    height: '100%',
    backgroundColor: '#58a6ff',
    borderRadius: '2px',
    transition: 'width 0.2s',
  },
  pendingError: {
    color: '#f85149',
    fontSize: '0.7rem',
  },
  removeButton: {
    background: 'none',
    border: 'none',
    color: '#8b949e',
    cursor: 'pointer',
    fontSize: '0.875rem',
    padding: '0 0.25rem',
    lineHeight: 1,
  },
};