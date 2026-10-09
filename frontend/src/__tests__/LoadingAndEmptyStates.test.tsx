import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import React from 'react';
import { LoadingState } from '../components/LoadingState';
import { EmptyState } from '../components/EmptyState';
import { ErrorState } from '../components/ErrorState';

describe('LoadingState Component', () => {
  it('renders loading state with accessible status and message', () => {
    render(<LoadingState message="Custom analyzing..." subtext="Custom subtext..." />);
    const container = screen.getByRole('status');
    expect(container).toBeInTheDocument();
    expect(screen.getByText('Custom analyzing...')).toBeInTheDocument();
    expect(screen.getByText('Custom subtext...')).toBeInTheDocument();
  });
});

describe('EmptyState Component', () => {
  it('renders title, description, and triggers onAction callback', () => {
    const handleAction = vi.fn();
    render(
      <EmptyState
        title="No repo found"
        description="Please select a repo."
        actionLabel="Run Scan"
        onAction={handleAction}
      />
    );
    expect(screen.getByText('No repo found')).toBeInTheDocument();
    expect(screen.getByText('Please select a repo.')).toBeInTheDocument();
    const btn = screen.getByRole('button', { name: /Run Scan/i });
    fireEvent.click(btn);
    expect(handleAction).toHaveBeenCalledTimes(1);
  });
});

describe('ErrorState Component', () => {
  it('renders error alert and retry button', () => {
    const handleRetry = vi.fn();
    render(
      <ErrorState
        title="Path error"
        message="Directory does not exist"
        onRetry={handleRetry}
      />
    );
    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(screen.getByText('Path error')).toBeInTheDocument();
    expect(screen.getByText('Directory does not exist')).toBeInTheDocument();
    const retryBtn = screen.getByRole('button', { name: /Retry Analysis/i });
    fireEvent.click(retryBtn);
    expect(handleRetry).toHaveBeenCalledTimes(1);
  });
});
