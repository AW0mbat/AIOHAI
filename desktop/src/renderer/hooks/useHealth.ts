import { useState, useEffect } from 'react';
import type { HealthSnapshot } from '../types/electron';

/**
 * Subscribe to health monitor updates from the main process.
 * Returns the latest health snapshot.
 */
export function useHealth(): HealthSnapshot | null {
  const [health, setHealth] = useState<HealthSnapshot | null>(null);

  useEffect(() => {
    // Initial check
    window.electronAPI?.health.checkNow().then((snapshot) => {
      if (snapshot) setHealth(snapshot);
    });

    // Subscribe to updates
    const unsubscribe = window.electronAPI?.health.onUpdate((snapshot) => {
      setHealth(snapshot);
    });

    return () => {
      unsubscribe?.();
    };
  }, []);

  return health;
}
