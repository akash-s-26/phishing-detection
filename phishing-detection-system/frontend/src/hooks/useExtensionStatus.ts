import { useState, useEffect, useCallback } from 'react';

export interface ExtensionStatus {
  isConnected: boolean;
  version: string | null;
  lastChecked: number | null;
  checkStatus: () => void;
  triggerScan: (url: string) => Promise<any>;
}

export function useExtensionStatus(): ExtensionStatus {
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const [version, setVersion] = useState<string | null>(null);
  const [lastChecked, setLastChecked] = useState<number | null>(null);

  const checkStatus = useCallback(() => {
    // Send window postMessage ping
    window.postMessage({ type: 'PHISHGUARD_PING' }, '*');
    setLastChecked(Date.now());
  }, []);

  useEffect(() => {
    function handleMessage(event: MessageEvent) {
      if (event.data && event.data.type === 'PHISHGUARD_PONG') {
        setIsConnected(true);
        setVersion(event.data.version || '2.0.0');
      }
    }

    window.addEventListener('message', handleMessage);
    checkStatus();

    const interval = setInterval(checkStatus, 4000);

    return () => {
      window.removeEventListener('message', handleMessage);
      clearInterval(interval);
    };
  }, [checkStatus]);

  const triggerScan = useCallback((url: string): Promise<any> => {
    return new Promise((resolve) => {
      const handler = (event: MessageEvent) => {
        if (event.data && event.data.type === 'PHISHGUARD_SCAN_RESPONSE') {
          window.removeEventListener('message', handler);
          resolve(event.data.result);
        }
      };

      window.addEventListener('message', handler);
      window.postMessage({ type: 'PHISHGUARD_TRIGGER_SCAN', url }, '*');

      setTimeout(() => {
        window.removeEventListener('message', handler);
        resolve(null);
      }, 5000);
    });
  }, []);

  return {
    isConnected,
    version,
    lastChecked,
    checkStatus,
    triggerScan
  };
}
