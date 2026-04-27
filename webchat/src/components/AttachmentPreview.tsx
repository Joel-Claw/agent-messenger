import React from 'react';
import { getAttachmentUrl, formatFileSize, isImageContentType, isAudioContentType, isVideoContentType } from '../services/api';
import type { Attachment } from '../types';

interface AttachmentPreviewProps {
  attachment: Attachment;
  token: string;
}

export function AttachmentPreview({ attachment, token }: AttachmentPreviewProps) {
  const url = getAttachmentUrl(attachment.id);
  const authUrl = `${url}?token=${encodeURIComponent(token)}`;

  if (isImageContentType(attachment.content_type)) {
    return (
      <div style={styles.container}>
        <a href={authUrl} target="_blank" rel="noopener noreferrer">
          <img
            src={authUrl}
            alt={attachment.filename}
            style={styles.image}
            loading="lazy"
          />
        </a>
        <div style={styles.caption}>
          <span style={styles.filename}>{attachment.filename}</span>
          <span style={styles.filesize}>{formatFileSize(attachment.size)}</span>
        </div>
      </div>
    );
  }

  if (isAudioContentType(attachment.content_type)) {
    return (
      <div style={styles.container}>
        <audio controls style={styles.audio} preload="metadata">
          <source src={authUrl} type={attachment.content_type} />
        </audio>
        <div style={styles.caption}>
          <span style={styles.filename}>{attachment.filename}</span>
          <span style={styles.filesize}>{formatFileSize(attachment.size)}</span>
        </div>
      </div>
    );
  }

  if (isVideoContentType(attachment.content_type)) {
    return (
      <div style={styles.container}>
        <video controls style={styles.video} preload="metadata">
          <source src={authUrl} type={attachment.content_type} />
        </video>
        <div style={styles.caption}>
          <span style={styles.filename}>{attachment.filename}</span>
          <span style={styles.filesize}>{formatFileSize(attachment.size)}</span>
        </div>
      </div>
    );
  }

  // Generic file: show download link
  return (
    <div style={styles.container}>
      <a
        href={authUrl}
        target="_blank"
        rel="noopener noreferrer"
        style={styles.fileLink}
      >
        <span style={styles.fileIcon}>{getFileIcon(attachment.content_type)}</span>
        <div style={styles.fileInfo}>
          <span style={styles.filename}>{attachment.filename}</span>
          <span style={styles.filesize}>{formatFileSize(attachment.size)}</span>
        </div>
      </a>
    </div>
  );
}

function getFileIcon(contentType: string): string {
  if (contentType === 'application/pdf') return '📄';
  if (contentType.startsWith('text/')) return '📝';
  if (contentType === 'application/json') return '{ }';
  return '📎';
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.25rem',
    marginBottom: '0.25rem',
  },
  image: {
    maxWidth: '280px',
    maxHeight: '200px',
    borderRadius: '8px',
    objectFit: 'cover' as const,
    cursor: 'pointer',
  },
  audio: {
    width: '220px',
    height: '36px',
    borderRadius: '4px',
  },
  video: {
    maxWidth: '280px',
    maxHeight: '200px',
    borderRadius: '8px',
  },
  caption: {
    display: 'flex',
    gap: '0.5rem',
    alignItems: 'center',
  },
  filename: {
    fontSize: '0.75rem',
    color: '#8b949e',
    maxWidth: '150px',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap' as const,
  },
  filesize: {
    fontSize: '0.625rem',
    color: '#6e7681',
  },
  fileLink: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    padding: '0.5rem 0.75rem',
    backgroundColor: 'rgba(255,255,255,0.05)',
    borderRadius: '8px',
    textDecoration: 'none',
    color: '#58a6ff',
    border: '1px solid #30363d',
    maxWidth: '240px',
    transition: 'background-color 0.15s',
  },
  fileIcon: {
    fontSize: '1.25rem',
    flexShrink: 0,
  },
  fileInfo: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '0.125rem',
    overflow: 'hidden',
  },
};